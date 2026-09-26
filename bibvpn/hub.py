"""Render the hub's files: probe Xray client, monitor config, Caddy (subscriptions)."""

import base64

from bibvpn.links import TRANSPORTS, node_links, vless_outbound
from bibvpn.state import State

PROBE_BASE_PORT = 21000
SUB_DIR = "/var/lib/bibvpn/subs"


def probe_checks(state: State) -> list[dict]:
    """One check per active node and transport, each with its own local SOCKS port."""
    checks = []
    for node in state.active_nodes():
        for transport in TRANSPORTS:
            checks.append(
                {
                    "id": f"{node.name}/{transport}",
                    "node": node.name,
                    "transport": transport,
                    "host": node.host,
                    "port": node.port,
                    "socks_port": PROBE_BASE_PORT + len(checks),
                }
            )
    return checks


def probe_xray_config(state: State) -> dict:
    """Xray client on the hub: SOCKS 127.0.0.1:<port> -> that node+transport."""
    inbounds, outbounds, rules = [], [], []
    nodes = {n.name: n for n in state.active_nodes()}
    for c in probe_checks(state):
        tag = c["id"].replace("/", "-")
        inbounds.append(
            {"tag": f"in-{tag}", "listen": "127.0.0.1", "port": c["socks_port"], "protocol": "socks", "settings": {}}
        )
        outbounds.append(vless_outbound(nodes[c["node"]], state.monitor.uuid, c["transport"], tag=f"out-{tag}"))
        rules.append({"inboundTag": [f"in-{tag}"], "outboundTag": f"out-{tag}"})
    # Traffic that matches no rule is dropped instead of leaving the hub directly.
    outbounds.append({"tag": "block", "protocol": "blackhole"})
    rules.append({"network": "tcp,udp", "outboundTag": "block"})
    return {"log": {"loglevel": "warning", "access": "none"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"rules": rules}}


def monitor_config(state: State) -> dict:
    m = state.monitor
    nodes = state.active_nodes()
    return {
        "fail_threshold": m.fail_threshold,
        "small_url": m.small_url,
        "large_url": m.large_url,
        "large_min_bytes": m.large_min_bytes,
        "telegram": {"token": m.telegram_token, "chat_id": m.telegram_chat_id, "api": m.telegram_api},
        "checks": probe_checks(state),
        "nodes": [n.name for n in nodes],
        "subscriptions": [
            {"token": u.sub_token, "user": u.name, "links": {n.name: node_links(n, u) for n in nodes}}
            for u in state.active_users()
        ],
        "sub_dir": SUB_DIR,
    }


def caddyfile(state: State) -> str:
    hub = state.hub
    title = base64.b64encode(hub.sub_title.encode()).decode()
    tls = "\n\ttls internal" if hub.tls == "internal" else ""
    # No `log` directive: Caddy keeps no access log, so subscription tokens (which
    # are credentials) never land on disk.
    return f"""# Rendered by bibvpn. Do not edit on the server: `bibvpn deploy` overwrites it.
{hub.domain} {{{tls}
	header {{
		-Server
		X-Content-Type-Options nosniff
		Referrer-Policy no-referrer
	}}
	handle_path /s/* {{
		root * {SUB_DIR}
		header Content-Type "text/plain; charset=utf-8"
		header Cache-Control "no-store"
		header Profile-Update-Interval "{hub.sub_update_hours}"
		header Profile-Title "base64:{title}"
		file_server
	}}
	handle {{
		respond 404
	}}
}}
"""
