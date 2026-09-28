#!/usr/bin/env python3
"""bibVPN monitor: runs on the hub (a server inside Russia) every few minutes.

For every node and transport it checks, from inside Russia:

1. TCP connect to node:443                 fails -> "unreachable"
   (IP/subnet blocked, or the server is down; skipped for UDP/Hysteria2)
2. a small HTTPS request through the tunnel fails -> "tunnel_failed"
   (protocol / SNI / fingerprint blocked, or Xray is not running)
3. a ~1 MB download through the tunnel      stalls -> "stalled"
   (the "freeze after 16-20 KB" block that hits whole hoster subnets)

Then it rewrites every user's subscription (working nodes and transports first,
broken ones marked) and sends a Telegram alert when a check has failed
`fail_threshold` rounds in a row, and again when it recovers.

Standard library only: this file is copied to the hub as-is and needs nothing but
python3 and curl. The tunnel itself is provided by a local Xray client
(bibvpn-probe.service) that exposes one SOCKS port per node and transport.
"""

import argparse
import base64
import datetime as dt
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

OK = "ok"
UNREACHABLE = "unreachable"
TUNNEL_FAILED = "tunnel_failed"
STALLED = "stalled"

EXPLAIN = {
    OK: "работает",
    UNREACHABLE: "порт недоступен из РФ: IP заблокирован или сервер выключен",
    TUNNEL_FAILED: "порт открыт, но туннель не работает: блокировка протокола/SNI/отпечатка или Xray не запущен",
    STALLED: "туннель открывается, но загрузка замирает: «заморозка» после первых килобайт, обычно блок подсети хостинга",
}

MARK_DOWN = "⚠ "


# --- probes -------------------------------------------------------------------


def tcp_connect(host: str, port: int, timeout: float = 5.0) -> float | None:
    """Milliseconds to connect, or None if the port cannot be reached."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (time.monotonic() - start) * 1000
    except OSError:
        return None


def run_curl(args: list[str], stdin: str | None = None, timeout: float = 60) -> tuple[int, str]:
    # Never let proxy variables from the environment redirect probes.
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    try:
        p = subprocess.run(
            ["curl", "-sS", *args], input=stdin, capture_output=True, text=True, timeout=timeout, env=env
        )
        return p.returncode, p.stdout.strip()
    except subprocess.TimeoutExpired:
        return 28, ""


def probe(check: dict, cfg: dict, tcp=tcp_connect, curl=run_curl) -> dict:
    """Run the three-step check for one node+transport and classify the result."""
    result = {"status": OK, "tcp_ms": None, "latency_ms": None, "speed_kbps": None}
    # UDP transports (Hysteria2) cannot be port-checked without speaking the protocol;
    # for them a failed tunnel covers "unreachable" too.
    if not check.get("udp"):
        result["tcp_ms"] = tcp(check["host"], check["port"])
        if result["tcp_ms"] is None:
            result["status"] = UNREACHABLE
            return result

    # -L: test URLs often redirect (CDNs, release downloads); a redirect is not a failure.
    socks = ["--socks5-hostname", f"127.0.0.1:{check['socks_port']}", "-L", "--max-redirs", "3"]
    rc, out = curl([*socks, "-o", "/dev/null", "-m", "15", "-w", "%{http_code} %{time_total}", cfg["small_url"]])
    code, _, seconds = out.partition(" ")
    if rc != 0 or not code.isdigit() or not 200 <= int(code) < 400:
        result["status"] = TUNNEL_FAILED
        return result
    result["latency_ms"] = round(float(seconds) * 1000)

    want = cfg["large_min_bytes"]
    rc, out = curl(
        [
            *socks, "-o", "/dev/null", "-m", "40", "--speed-time", "10", "--speed-limit", "4096",
            "-r", f"0-{want * 4 - 1}", "-w", "%{size_download} %{speed_download}", cfg["large_url"],
        ]
    )
    size, _, speed = out.partition(" ")
    if not size.isdigit() or int(size) < want:
        result["status"] = STALLED
        return result
    result["speed_kbps"] = round(float(speed or 0) * 8 / 1000)
    return result


# --- state machine --------------------------------------------------------------


def update_state(prev: dict, results: dict, threshold: int, now: str) -> tuple[dict, list[tuple[str, str, dict]]]:
    """Track consecutive failures per check; emit ("down"|"up", check_id, result)
    events once a failure persisted `threshold` rounds and when it recovers."""
    state, events = {}, []
    for cid, res in results.items():
        old = prev.get(cid, {"fails": 0, "alerted": False, "since": now, "status": OK})
        entry = dict(old)
        if res["status"] == OK:
            if old["alerted"]:
                events.append(("up", cid, res))
            entry.update(fails=0, alerted=False)
        else:
            entry["fails"] = old["fails"] + 1
            if entry["fails"] >= threshold and not old["alerted"]:
                events.append(("down", cid, res))
                entry["alerted"] = True
        if res["status"] != old["status"]:
            entry["since"] = now
        entry["status"] = res["status"]
        state[cid] = entry
    return state, events


# --- subscriptions --------------------------------------------------------------


def _mark(link: str) -> str:
    base, _, label = link.partition("#")
    return f"{base}#{quote(MARK_DOWN)}{label}"


def build_subscription(sub: dict, node_order: list[str], results: dict) -> str:
    """Working nodes first (fastest first), inside a node working transports first;
    broken entries stay in the list but are marked, because the hub sees Russia
    through one ISP and a node it cannot reach may still work for users elsewhere."""

    def status(node, transport):
        return results.get(f"{node}/{transport}", {}).get("status", OK)

    def node_rank(node):
        working = [r for t in sub["links"][node] if (r := results.get(f"{node}/{t}", {})).get("status", OK) == OK]
        latency = min((r.get("latency_ms") or 0 for r in working), default=0)
        return (0 if working else 1, latency, node_order.index(node))

    lines = []
    for node in sorted(sub["links"], key=node_rank):
        transports = sorted(sub["links"][node].items(), key=lambda kv: status(node, kv[0]) != OK)
        for transport, link in transports:
            lines.append(link if status(node, transport) == OK else _mark(link))
    return base64.b64encode("\n".join(lines).encode()).decode()


def _atomic_write(path: Path, text: str, mode: int) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def write_subscriptions(sub_dir: Path, bodies: dict[str, str]) -> None:
    sub_dir.mkdir(parents=True, exist_ok=True)
    for token, body in bodies.items():
        _atomic_write(sub_dir / token, body + "\n", 0o640)
    for stale in sub_dir.iterdir():  # revoked users / rotated tokens
        if stale.name not in bodies and not stale.name.startswith(".tmp-"):
            stale.unlink()


# --- alerts ---------------------------------------------------------------------


def _curl_quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def send_telegram(cfg: dict, text: str, via_socks: list[int], curl=run_curl) -> bool | None:
    """Telegram is blocked in Russia, so try through each working tunnel first and
    fall back to a direct request. The token goes via stdin, never argv.
    Returns None when alerts are not configured."""
    tg = cfg["telegram"]
    if not tg["token"] or not tg["chat_id"]:
        return None
    base = [
        f"url = {_curl_quote(tg['api'].rstrip('/') + '/bot' + tg['token'] + '/sendMessage')}",
        f"data-urlencode = {_curl_quote('chat_id=' + tg['chat_id'])}",
        f"data-urlencode = {_curl_quote('text=' + text)}",
        'max-time = "15"',
        'output = "/dev/null"',
        'write-out = "%{http_code}"',
    ]
    for proxy in [*(f"127.0.0.1:{p}" for p in via_socks), None]:
        conf = base + ([f"socks5-hostname = {_curl_quote(proxy)}"] if proxy else [])
        rc, out = curl(["-K", "-"], stdin="\n".join(conf) + "\n")
        if rc == 0 and out == "200":
            return True
    return False


def format_events(events: list, results: dict) -> str:
    lines = []
    for kind, cid, res in events:
        if kind == "down":
            lines.append(f"🔴 {cid}: {EXPLAIN[res['status']]}")
        else:
            lines.append(f"🟢 {cid}: снова работает ({res.get('latency_ms')} мс)")
    total = len(results)
    ok = sum(r["status"] == OK for r in results.values())
    lines.append(f"Сейчас работает {ok} из {total} проверок.")
    return "bibVPN\n" + "\n".join(lines)


# --- main -----------------------------------------------------------------------


def run_round(cfg: dict, state_dir: Path, probe_fn=probe, send_fn=send_telegram) -> dict:
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    checks = cfg["checks"]
    with ThreadPoolExecutor(max_workers=max(1, min(8, len(checks)))) as pool:
        outcomes = list(pool.map(lambda c: probe_fn(c, cfg), checks))
    results = {c["id"]: r for c, r in zip(checks, outcomes)}

    state_file = state_dir / "state.json"
    prev = json.loads(state_file.read_text()) if state_file.exists() else {}
    state, events = update_state(prev, results, cfg["fail_threshold"], now)

    bodies = {s["token"]: build_subscription(s, cfg["nodes"], results) for s in cfg["subscriptions"]}
    write_subscriptions(Path(cfg["sub_dir"]), bodies)

    alert_sent = None
    if events:
        working_ports = [c["socks_port"] for c in checks if results[c["id"]]["status"] == OK]
        alert_sent = send_fn(cfg, format_events(events, results), working_ports)
        if alert_sent is False:
            # Not delivered: forget the transition so the next round tries again.
            for kind, cid, _ in events:
                state[cid]["alerted"] = kind == "up"

    status = {
        "time": now,
        "checks": {cid: {**results[cid], "fails": state[cid]["fails"], "since": state[cid]["since"]} for cid in results},
        "events": [[k, c] for k, c, _ in events],
        "alert_sent": alert_sent,
    }
    _atomic_write(state_file, json.dumps(state), 0o600)
    _atomic_write(state_dir / "status.json", json.dumps(status, indent=2, ensure_ascii=False) + "\n", 0o644)
    return status


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="bibVPN hub monitor (one round per run)")
    p.add_argument("--config", type=Path, default=Path("/etc/bibvpn/monitor.json"))
    p.add_argument("--state-dir", type=Path, default=Path("/var/lib/bibvpn-monitor"))
    p.add_argument("--test-alert", action="store_true", help="only send a test Telegram message")
    args = p.parse_args(argv)
    cfg = json.loads(args.config.read_text())

    if args.test_alert:
        ports = [c["socks_port"] for c in cfg["checks"]]
        ok = send_telegram(cfg, "bibVPN: тестовое уведомление, мониторинг работает ✅", ports)
        if ok is None:
            print("Telegram is not configured: bibvpn monitor set --telegram-token ... --telegram-chat-id ...")
        else:
            print("sent" if ok else "NOT sent (check token, chat id, and that you pressed Start in the bot)")
        return 0 if ok else 1

    status = run_round(cfg, args.state_dir)
    for cid, res in status["checks"].items():
        print(f"{cid:24} {res['status']:14} tcp={res['tcp_ms'] and round(res['tcp_ms'])}ms "
              f"latency={res['latency_ms']}ms speed={res['speed_kbps']}kbps")
    return 0


if __name__ == "__main__":
    sys.exit(main())
