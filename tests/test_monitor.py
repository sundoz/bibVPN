"""Monitor logic (runs on the hub) with fake network probes."""

import base64
import json
import os
import stat
from urllib.parse import unquote

import pytest

from bibvpn import monitor as mon

CFG = {"small_url": "https://small.example/", "large_url": "https://large.example/", "large_min_bytes": 262144}
CHECK = {"id": "fi1/vision", "host": "203.0.113.5", "port": 443, "socks_port": 21000}


def fake_curl(small=(0, "204 0.120"), large=(0, "1048576 250000.0")):
    calls = []

    def curl(args, stdin=None, timeout=60):
        calls.append((args, stdin))
        return small if CFG["small_url"] in args else large

    curl.calls = calls
    return curl


# --- probe classification -------------------------------------------------------


def test_probe_ok():
    r = mon.probe(CHECK, CFG, tcp=lambda h, p: 12.5, curl=fake_curl())
    assert r == {"status": "ok", "tcp_ms": 12.5, "latency_ms": 120, "speed_kbps": 2000}


def test_probe_unreachable_skips_tunnel():
    curl = fake_curl()
    r = mon.probe(CHECK, CFG, tcp=lambda h, p: None, curl=curl)
    assert r["status"] == mon.UNREACHABLE and curl.calls == []


@pytest.mark.parametrize("small", [(7, ""), (0, "000 0.0"), (0, "502 1.0"), (97, "000 0")])
def test_probe_tunnel_failed(small):
    assert mon.probe(CHECK, CFG, tcp=lambda h, p: 1.0, curl=fake_curl(small=small))["status"] == mon.TUNNEL_FAILED


@pytest.mark.parametrize("large", [(28, "16384 1200.0"), (28, ""), (0, "999 10.0")])
def test_probe_stalled(large):
    assert mon.probe(CHECK, CFG, tcp=lambda h, p: 1.0, curl=fake_curl(large=large))["status"] == mon.STALLED


def test_probe_goes_through_the_tunnel():
    curl = fake_curl()
    mon.probe(CHECK, CFG, tcp=lambda h, p: 1.0, curl=curl)
    for args, _ in curl.calls:
        assert args[args.index("--socks5-hostname") + 1] == "127.0.0.1:21000"
        assert "-L" in args, "redirects must be followed or every CDN URL looks broken"


def test_curl_ignores_proxy_environment(monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen.update(kw["env"])
        raise mon.subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setenv("HTTPS_PROXY", "http://evil:1")
    monkeypatch.setenv("no_proxy", "*")
    monkeypatch.setattr(mon.subprocess, "run", fake_run)
    assert mon.run_curl(["x"]) == (28, "")
    assert not any("proxy" in k.lower() for k in seen)


# --- alert state machine ----------------------------------------------------------

DOWN = {"status": mon.STALLED}
UP = {"status": mon.OK, "latency_ms": 50}


def test_alert_after_threshold_once_then_recovery():
    state, ev = mon.update_state({}, {"a": DOWN}, 2, "t1")
    assert ev == [] and state["a"]["fails"] == 1
    state, ev = mon.update_state(state, {"a": DOWN}, 2, "t2")
    assert [e[0] for e in ev] == ["down"]
    state, ev = mon.update_state(state, {"a": DOWN}, 2, "t3")
    assert ev == [], "no repeated alerts while still down"
    state, ev = mon.update_state(state, {"a": UP}, 2, "t4")
    assert [e[0] for e in ev] == ["up"] and state["a"]["fails"] == 0


def test_single_glitch_does_not_alert():
    state, _ = mon.update_state({}, {"a": DOWN}, 2, "t1")
    state, ev = mon.update_state(state, {"a": UP}, 2, "t2")
    assert ev == [] and state["a"]["fails"] == 0


def test_since_tracks_status_changes():
    state, _ = mon.update_state({}, {"a": UP}, 2, "t1")
    state, _ = mon.update_state(state, {"a": UP}, 2, "t2")
    assert state["a"]["since"] == "t1"
    state, _ = mon.update_state(state, {"a": DOWN}, 2, "t3")
    assert state["a"]["since"] == "t3"


# --- subscriptions ----------------------------------------------------------------

SUB = {
    "token": "t" * 32,
    "user": "me",
    "links": {
        "fi1": {"vision": "vless://u@1.1.1.1:443?a#bib-fi1-vision", "xhttp": "vless://u@1.1.1.1:443?b#bib-fi1-xhttp"},
        "nl1": {"vision": "vless://u@2.2.2.2:443?a#bib-nl1-vision", "xhttp": "vless://u@2.2.2.2:443?b#bib-nl1-xhttp"},
    },
}


def decode(body):
    return [unquote(line.split("#")[1]) for line in base64.b64decode(body).decode().splitlines()]


def ok(ms):
    return {"status": mon.OK, "latency_ms": ms}


def test_subscription_all_ok_keeps_fastest_first():
    results = {"fi1/vision": ok(90), "fi1/xhttp": ok(95), "nl1/vision": ok(40), "nl1/xhttp": ok(45)}
    assert decode(mon.build_subscription(SUB, ["fi1", "nl1"], results)) == [
        "bib-nl1-vision", "bib-nl1-xhttp", "bib-fi1-vision", "bib-fi1-xhttp",
    ]


def test_subscription_down_node_last_and_marked():
    results = {"fi1/vision": DOWN, "fi1/xhttp": DOWN, "nl1/vision": ok(40), "nl1/xhttp": ok(45)}
    assert decode(mon.build_subscription(SUB, ["fi1", "nl1"], results)) == [
        "bib-nl1-vision", "bib-nl1-xhttp", "⚠ bib-fi1-vision", "⚠ bib-fi1-xhttp",
    ]


def test_subscription_working_transport_first():
    results = {"fi1/vision": DOWN, "fi1/xhttp": ok(60), "nl1/vision": DOWN, "nl1/xhttp": DOWN}
    assert decode(mon.build_subscription(SUB, ["fi1", "nl1"], results))[:2] == ["bib-fi1-xhttp", "⚠ bib-fi1-vision"]


def test_subscription_never_empty():
    results = {k: DOWN for k in ("fi1/vision", "fi1/xhttp", "nl1/vision", "nl1/xhttp")}
    assert len(decode(mon.build_subscription(SUB, ["fi1", "nl1"], results))) == 4


def test_subscription_unknown_node_treated_as_working():
    assert decode(mon.build_subscription(SUB, ["fi1", "nl1"], {}))[0] == "bib-fi1-vision"


def test_write_subscriptions_removes_revoked(tmp_path):
    (tmp_path / "revoked-token").write_text("old")
    mon.write_subscriptions(tmp_path, {"abc": "body"})
    assert sorted(p.name for p in tmp_path.iterdir()) == ["abc"]
    assert stat.S_IMODE(os.stat(tmp_path / "abc").st_mode) == 0o640


# --- telegram -----------------------------------------------------------------------

TG_CFG = {"telegram": {"token": "123456:" + "A" * 35, "chat_id": "42", "api": "https://api.telegram.org"}}


def test_telegram_not_configured():
    assert mon.send_telegram({"telegram": {"token": "", "chat_id": "", "api": "x"}}, "hi", []) is None


def test_telegram_tries_tunnels_then_direct_and_hides_token():
    calls = []

    def curl(args, stdin=None, timeout=60):
        calls.append((args, stdin))
        return (0, "200") if len(calls) == 3 else (7, "")

    assert mon.send_telegram(TG_CFG, 'line1\n"quoted" \\ back', [21000, 21001], curl=curl) is True
    assert [("socks5-hostname" in c[1]) for c in calls] == [True, True, False]
    for args, conf in calls:
        assert args == ["-K", "-"], "token must not appear in argv"
        assert TG_CFG["telegram"]["token"] in conf
    assert 'text=line1\\n\\"quoted\\" \\\\ back' in calls[0][1]


def test_telegram_all_routes_fail():
    assert mon.send_telegram(TG_CFG, "x", [21000], curl=lambda a, stdin=None, timeout=60: (7, "")) is False


# --- a full round ----------------------------------------------------------------------


@pytest.fixture
def round_cfg(tmp_path):
    return {
        **CFG, **TG_CFG,
        "fail_threshold": 1,
        "checks": [{**CHECK, "id": "fi1/vision", "socks_port": 21000}, {**CHECK, "id": "fi1/xhttp", "socks_port": 21001}],
        "nodes": ["fi1"],
        "subscriptions": [{**SUB, "links": {"fi1": SUB["links"]["fi1"]}}],
        "sub_dir": str(tmp_path / "subs"),
    }


def test_run_round_writes_status_and_subs(tmp_path, round_cfg):
    results = {"fi1/vision": ok(30), "fi1/xhttp": DOWN}
    sent = []
    status = mon.run_round(round_cfg, tmp_path, probe_fn=lambda c, cfg: results[c["id"]],
                           send_fn=lambda cfg, text, ports: sent.append((text, ports)) or True)
    assert status["checks"]["fi1/xhttp"]["status"] == mon.STALLED
    assert json.loads((tmp_path / "status.json").read_text())["events"] == [["down", "fi1/xhttp"]]
    assert "fi1/xhttp" in sent[0][0] and sent[0][1] == [21000], "alert goes via the working tunnel"
    assert decode((tmp_path / "subs" / ("t" * 32)).read_text()) == ["bib-fi1-vision", "⚠ bib-fi1-xhttp"]


def test_undelivered_alert_is_retried(tmp_path, round_cfg):
    results = {"fi1/vision": DOWN, "fi1/xhttp": DOWN}
    attempts = []
    send = lambda cfg, text, ports: attempts.append(text) or False  # noqa: E731
    mon.run_round(round_cfg, tmp_path, probe_fn=lambda c, cfg: results[c["id"]], send_fn=send)
    mon.run_round(round_cfg, tmp_path, probe_fn=lambda c, cfg: results[c["id"]], send_fn=send)
    assert len(attempts) == 2


def test_main_test_alert(tmp_path, round_cfg, monkeypatch, capsys):
    cfg_path = tmp_path / "monitor.json"
    cfg_path.write_text(json.dumps(round_cfg))
    monkeypatch.setattr(mon, "send_telegram", lambda cfg, text, ports: True)
    assert mon.main(["--config", str(cfg_path), "--test-alert"]) == 0
    assert "sent" in capsys.readouterr().out
