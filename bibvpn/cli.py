"""bibvpn command line: edit the state file, render configs, deploy."""

import argparse
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
    s.nodes.remove(s.node(args.name))
    _save(args, s)
    print(f"removed node {args.name} from state (the server itself is untouched)")
    return 0


def cmd_node_set(args) -> int:
    s = _load(args)
    node = s.node(args.name)
    if args.enabled is not None:
        node.enabled = args.enabled
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


def cmd_render(args) -> int:
    s = _load(args)
    for path in render.render_all(s, args.build_dir):
        print(f"wrote {path}")
    return 0


def cmd_deploy(args) -> int:
    s = _load(args)
    if not s.active_nodes():
        print("no active nodes; add one with `bibvpn node add`")
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
    nr = node.add_parser("rm")
    nr.add_argument("name")
    nr.set_defaults(func=cmd_node_rm)
    ns = node.add_parser("set", help="change a node")
    ns.add_argument("name")
    ns.add_argument("--enable", dest="enabled", action="store_const", const=True)
    ns.add_argument("--disable", dest="enabled", action="store_const", const=False)
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
