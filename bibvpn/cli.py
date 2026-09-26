"""bibvpn command line: edit the state file, render configs, deploy."""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from bibvpn import links, render, state as st, target

REPO_ROOT = Path(__file__).resolve().parent.parent
PLAYBOOK = REPO_ROOT / "ansible" / "site.yml"


def _load(args) -> st.State:
    return st.load(args.state)


def _save(args, s: st.State) -> None:
    st.save(s, args.state)


def cmd_init(args) -> int:
    if args.state.exists():
        print(f"{args.state} already exists")
        return 1
    st.save(st.State(), args.state)
    print(f"created {args.state} (keep it private and backed up: it holds all keys)")
    return 0


def cmd_check_target(args) -> int:
    report = target.check_target(args.host)
    print(f"{report.host}: TLS={report.tls_version or '-'} ALPN={report.alpn or '-'} RTT={report.rtt_ms:.0f}ms")
    for w in report.warnings:
        print(f"  warning: {w}")
    for p in report.problems:
        print(f"  problem: {p}")
    print("  OK" if report.ok else "  NOT SUITABLE")
    return 0 if report.ok else 1


def cmd_node_add(args) -> int:
    s = _load(args)
    if not args.force:
        report = target.check_target(args.sni)
        for w in report.warnings:
            print(f"warning: {w}")
        if not report.ok:
            for p in report.problems:
                print(f"problem with --sni {args.sni}: {p}")
            print("choose another --sni, or pass --force if the check cannot run from here")
            return 1
    node = s.add_node(
        args.name, args.host, sni=args.sni, ssh_user=args.ssh_user, ssh_port=args.ssh_port, port=args.port
    )
    _save(args, s)
    print(f"added node {node.name} ({node.host}), impersonating {node.reality.sni}")
    print("next: bibvpn deploy")
    return 0


def cmd_node_list(args) -> int:
    for n in _load(args).nodes:
        flag = "" if n.enabled else "  [disabled]"
        print(f"{n.name:12} {n.host:40} :{n.port}  sni={n.reality.sni}  role={n.role}{flag}")
    return 0


def cmd_node_rm(args) -> int:
    s = _load(args)
    node = s.node(args.name)
    if node.enabled and not args.force:
        print(f"node {node.name} is enabled: removing it from state would leave Xray running on the")
        print("server with every existing link still working. First stop it:")
        print(f"  bibvpn node set {node.name} --disable && bibvpn deploy")
        print(f"then `bibvpn node rm {node.name}` (or pass --force if the server is already gone).")
        return 1
    s.nodes.remove(node)
    _save(args, s)
    print(f"removed node {args.name} from state")
    return 0


def cmd_node_set(args) -> int:
    s = _load(args)
    node = s.node(args.name)
    if args.enabled is not None:
        node.enabled = args.enabled
        if not node.enabled:
            print("on the next deploy Xray on this server is stopped, its config (keys, UUIDs)")
            print("deleted and port closed: all links to it stop working. It also leaves")
            print("subscriptions and monitoring.")
    if args.sni:
        node.reality.sni = args.sni
    if args.rotate_keys:
        s.rotate_node_keys(args.name)
        print("new Reality keys generated: every user must re-import links for this node")
    _save(args, s)
    print("updated; next: bibvpn deploy")
    return 0


def cmd_user_add(args) -> int:
    s = _load(args)
    user = s.add_user(args.name, note=args.note)
    _save(args, s)
    print(f"added user {user.name}; next: bibvpn deploy, then bibvpn links {user.name}")
    return 0


def cmd_user_list(args) -> int:
    for u in _load(args).users:
        flag = "" if u.enabled else "  [disabled]"
        print(f"{u.name:16} {u.created}  {u.note}{flag}")
    return 0


def cmd_user_rm(args) -> int:
    s = _load(args)
    s.remove_user(args.name)
    _save(args, s)
    print(f"removed user {args.name}; run bibvpn deploy to revoke access")
    return 0


def cmd_user_set(args) -> int:
    s = _load(args)
    user = s.user(args.name)
    user.enabled = args.enabled
    _save(args, s)
    print(f"user {user.name} {'enabled' if user.enabled else 'disabled'}; next: bibvpn deploy")
    return 0


def cmd_links(args) -> int:
    s = _load(args)
    user = s.user(args.name)
    nodes = s.active_nodes()
    if not nodes:
        print("no active nodes")
        return 1
    if args.subscription:
        print(links.subscription(nodes, user))
        return 0
    for link in links.user_links(nodes, user):
        print(link)
        if args.qr:
            _print_qr(link)
    return 0


def _print_qr(text: str) -> None:
    try:
        import qrcode
    except ImportError:
        print("(install the `qr` extra to print QR codes: pip install -e '.[qr]')")
        return
    qr = qrcode.QRCode(border=1)
    qr.add_data(text)
    qr.print_ascii(invert=True)


def cmd_sub(args) -> int:
    s = _load(args)
    if not s.hub:
        print("subscriptions need a hub: bibvpn hub set <IP of a server in Russia>")
        return 1
    url = links.subscription_url(s.hub, s.user(args.name))
    print(url)
    if args.qr:
        _print_qr(url)
    return 0


def cmd_user_rotate_sub(args) -> int:
    s = _load(args)
    s.rotate_sub_token(args.name)
    _save(args, s)
    print(f"new subscription URL for {args.name} (the old one stops working after deploy):")
    print(links.subscription_url(s.hub, s.user(args.name)) if s.hub else "(no hub configured)")
    return 0


def cmd_hub_set(args) -> int:
    s = _load(args)
    kwargs = {k: v for k, v in (("ssh_user", args.ssh_user), ("ssh_port", args.ssh_port), ("tls", args.tls),
                                ("sub_update_hours", args.update_hours), ("sub_title", args.title)) if v is not None}
    hub = s.set_hub(args.host, domain=args.domain, **kwargs)
    _save(args, s)
    print(f"hub {hub.host}, subscriptions at https://{hub.domain}/s/<token>")
    print("next: bibvpn deploy")
    return 0


def cmd_hub_rm(args) -> int:
    s = _load(args)
    s.hub = None
    _save(args, s)
    print("hub removed from state (the server itself is untouched); run bibvpn deploy")
    return 0


def cmd_monitor_set(args) -> int:
    s = _load(args)
    m = s.monitor
    for field, value in (
        ("interval_min", args.interval), ("fail_threshold", args.threshold),
        ("telegram_token", args.telegram_token), ("telegram_chat_id", args.telegram_chat_id),
        ("telegram_api", args.telegram_api), ("small_url", args.small_url),
        ("large_url", args.large_url), ("large_min_bytes", args.large_min_bytes),
    ):
        if value is not None:
            setattr(m, field, value)
    _save(args, s)
    print("monitor settings saved; next: bibvpn deploy")
    return 0


def _hub_ssh(s: st.State, args, remote: str) -> list[str]:
    cmd = ["ssh", "-p", str(s.hub.ssh_port)]
    if args.identity:
        cmd += ["-i", str(args.identity)]
    for opt in args.ssh_options:
        cmd += ["-o", opt]
    return [*cmd, f"{s.hub.ssh_user}@{s.hub.host}", remote]


def cmd_monitor_test(args) -> int:
    s = _load(args)
    if not s.hub:
        print("no hub configured")
        return 1
    remote = "runuser -u bibvpn-monitor -- python3 /usr/local/lib/bibvpn/monitor.py --test-alert"
    return subprocess.call(_hub_ssh(s, args, remote))


STATUS_TEXT = {
    "ok": "работает",
    "unreachable": "порт недоступен из РФ (IP заблокирован или сервер выключен)",
    "tunnel_failed": "туннель не устанавливается (блок протокола/SNI или Xray не запущен)",
    "stalled": "загрузка замирает (заморозка после первых КБ, блок подсети хостинга)",
}


def cmd_status(args) -> int:
    s = _load(args)
    if not s.hub:
        print("monitoring needs a hub: bibvpn hub set <IP of a server in Russia>")
        return 1
    remote = "cat /var/lib/bibvpn-monitor/status.json"
    p = subprocess.run(_hub_ssh(s, args, remote), capture_output=True, text=True)
    if p.returncode != 0:
        print(f"cannot read status from the hub: {p.stderr.strip()}")
        return 1
    status = json.loads(p.stdout)
    print(f"checked from the hub at {status['time']}")
    for cid, r in status["checks"].items():
        mark = "OK  " if r["status"] == "ok" else "FAIL"
        extra = f"{r['latency_ms']} ms, {r['speed_kbps']} kbit/s" if r["status"] == "ok" else f"since {r['since']}"
        print(f"  {mark} {cid:22} {STATUS_TEXT.get(r['status'], r['status'])}; {extra}")
    return 0 if all(r["status"] == "ok" for r in status["checks"].values()) else 3


def cmd_render(args) -> int:
    s = _load(args)
    for path in render.render_all(s, args.build_dir):
        print(f"wrote {path}")
    return 0


def cmd_deploy(args) -> int:
    s = _load(args)
    # Disabled nodes still need a deploy (that is what stops them), so only an empty
    # state has nothing to do.
    if not s.nodes and not s.hub:
        print("no nodes; add one with `bibvpn node add`")
        return 1
    render.render_all(s, args.build_dir)
    # Prefer the ansible-playbook installed next to this interpreter (same venv).
    playbook_bin = shutil.which("ansible-playbook", path=str(Path(sys.executable).parent)) or shutil.which(
        "ansible-playbook"
    )
    if not playbook_bin:
        print("ansible-playbook not found: pip install -e '.[deploy]'")
        return 1
    cmd = [playbook_bin, "-i", str(args.build_dir / "inventory.yml"), str(PLAYBOOK)]
    if args.limit:
        cmd += ["--limit", args.limit]
    if args.check:
        cmd += ["--check", "--diff"]
    cmd += args.ansible_args
    print("+ " + " ".join(cmd))
    return subprocess.call(cmd, cwd=REPO_ROOT / "ansible")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bibvpn", description=__doc__)
    p.add_argument("--state", type=Path, default=st.default_path(), help="state file (env BIBVPN_STATE)")
    p.add_argument("--build-dir", type=Path, default=Path("build"), help="where rendered files go")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create an empty state file").set_defaults(func=cmd_init)

    ct = sub.add_parser("check-target", help="check a site as a Reality SNI candidate")
    ct.add_argument("host")
    ct.set_defaults(func=cmd_check_target)

    node = sub.add_parser("node", help="manage servers").add_subparsers(dest="node_cmd", required=True)
    na = node.add_parser("add", help="register a server and generate its Reality keys")
    na.add_argument("name")
    na.add_argument("host", help="public IP or hostname of the server")
    na.add_argument("--sni", required=True, help="foreign site to impersonate (see check-target)")
    na.add_argument("--ssh-user", default="root")
    na.add_argument("--ssh-port", type=int, default=22)
    na.add_argument("--port", type=int, default=443, help="public port (keep 443 unless you must)")
    na.add_argument("--force", action="store_true", help="skip the SNI check")
    na.set_defaults(func=cmd_node_add)
    node.add_parser("list").set_defaults(func=cmd_node_list)
    nr = node.add_parser("rm", help="forget a node (disable + deploy it first)")
    nr.add_argument("name")
    nr.add_argument("--force", action="store_true", help="remove even if enabled (server already gone)")
    nr.set_defaults(func=cmd_node_rm)
    ns = node.add_parser("set", help="change a node")
    ns.add_argument("name")
    ns.add_argument("--enable", dest="enabled", action="store_const", const=True)
    ns.add_argument(
        "--disable", dest="enabled", action="store_const", const=False,
        help="next deploy stops Xray there and deletes its config; links stop working",
    )
    ns.add_argument("--sni")
    ns.add_argument("--rotate-keys", action="store_true", help="new Reality keys (invalidates links)")
    ns.set_defaults(func=cmd_node_set)

    user = sub.add_parser("user", help="manage users").add_subparsers(dest="user_cmd", required=True)
    ua = user.add_parser("add")
    ua.add_argument("name")
    ua.add_argument("--note", default="")
    ua.set_defaults(func=cmd_user_add)
    user.add_parser("list").set_defaults(func=cmd_user_list)
    ur = user.add_parser("rm")
    ur.add_argument("name")
    ur.set_defaults(func=cmd_user_rm)
    for verb, value in (("enable", True), ("disable", False)):
        up = user.add_parser(verb)
        up.add_argument("name")
        up.set_defaults(func=cmd_user_set, enabled=value)

    urs = user.add_parser("rotate-sub", help="new subscription URL (if the old one leaked)")
    urs.add_argument("name")
    urs.set_defaults(func=cmd_user_rotate_sub)

    sb = sub.add_parser("sub", help="print a user's subscription URL (needs a hub)")
    sb.add_argument("name")
    sb.add_argument("--qr", action="store_true")
    sb.set_defaults(func=cmd_sub)

    hub = sub.add_parser("hub", help="subscription + monitoring server").add_subparsers(dest="hub_cmd", required=True)
    hs = hub.add_parser("set", help="register the hub (ideally a VPS in Russia)")
    hs.add_argument("host")
    hs.add_argument("--domain", help="DNS name for HTTPS (default: <ip>.sslip.io)")
    hs.add_argument("--ssh-user")
    hs.add_argument("--ssh-port", type=int)
    hs.add_argument("--tls", choices=st.TLS_MODES, help="internal = self-signed, tests only")
    hs.add_argument("--update-hours", type=int, help="how often clients refresh the subscription")
    hs.add_argument("--title", help="subscription name shown in clients")
    hs.set_defaults(func=cmd_hub_set)
    hub.add_parser("rm").set_defaults(func=cmd_hub_rm)

    mon = sub.add_parser("monitor", help="monitoring settings").add_subparsers(dest="mon_cmd", required=True)
    ms = mon.add_parser("set")
    ms.add_argument("--interval", type=int, help="minutes between checks")
    ms.add_argument("--threshold", type=int, help="failed rounds in a row before an alert")
    ms.add_argument("--telegram-token", help="bot token from @BotFather")
    ms.add_argument("--telegram-chat-id", help="your chat id (e.g. from @userinfobot)")
    ms.add_argument("--telegram-api", help=argparse.SUPPRESS)
    ms.add_argument("--small-url")
    ms.add_argument("--large-url")
    ms.add_argument("--large-min-bytes", type=int)
    ms.set_defaults(func=cmd_monitor_set)
    mt = mon.add_parser("test", help="send a test Telegram alert from the hub")
    mt.add_argument("-i", "--identity", type=Path, help="SSH private key")
    mt.add_argument("-o", dest="ssh_options", action="append", default=[], help="extra ssh -o option")
    mt.set_defaults(func=cmd_monitor_test)

    stt = sub.add_parser("status", help="latest check results from the hub")
    stt.add_argument("-i", "--identity", type=Path, help="SSH private key")
    stt.add_argument("-o", dest="ssh_options", action="append", default=[], help="extra ssh -o option")
    stt.set_defaults(func=cmd_status)

    lk = sub.add_parser("links", help="print a user's share links")
    lk.add_argument("name")
    lk.add_argument("--qr", action="store_true", help="also print QR codes")
    lk.add_argument("--subscription", action="store_true", help="print base64 subscription body")
    lk.set_defaults(func=cmd_links)

    sub.add_parser("render", help="write configs and inventory to the build dir").set_defaults(func=cmd_render)

    dp = sub.add_parser(
        "deploy",
        help="render, then apply to servers with Ansible",
        description="Unknown options are passed through to ansible-playbook (e.g. --private-key, -v).",
    )
    dp.add_argument("--limit", help="only these nodes (Ansible --limit syntax)")
    dp.add_argument("--check", action="store_true", help="dry run with diff")
    dp.set_defaults(func=cmd_deploy)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)
    if extra and args.cmd != "deploy":
        parser.error(f"unrecognized arguments: {' '.join(extra)}")
    args.ansible_args = extra
    args.build_dir = args.build_dir.resolve()
    try:
        return args.func(args)
    except st.StateError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
