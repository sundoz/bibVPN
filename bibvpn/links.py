"""Client-side artefacts: vless:// share links and base64 subscriptions.

Share links are understood by all mainstream clients (Hiddify, v2rayNG, v2rayN, Happ,
v2RayTun, Streisand, NekoBox, ...), which is what keeps us cross-platform without
writing our own client.
"""

import base64
from urllib.parse import quote, urlencode

from bibvpn.state import Hub, Node, User
from bibvpn.xray import VISION_FLOW


def _host(node: Node) -> str:
    return f"[{node.host}]" if ":" in node.host else node.host


def _reality_params(node: Node) -> dict:
    r = node.reality
    return {
        "encryption": "none",
        "security": "reality",
        "sni": r.sni,
        "fp": r.fingerprint,
        "pbk": r.public_key,
        "sid": r.short_ids[0],
    }


TRANSPORTS = ("vision", "xhttp")


def vision_link(node: Node, user: User) -> str:
    params = {**_reality_params(node), "type": "tcp", "flow": VISION_FLOW}
    return _link(node, user, params, "vision")


def xhttp_link(node: Node, user: User) -> str:
    params = {**_reality_params(node), "type": "xhttp", "path": node.xhttp_path, "mode": "auto"}
    return _link(node, user, params, "xhttp")


def _link(node: Node, user: User, params: dict, transport: str) -> str:
    label = quote(f"bib-{node.name}-{transport}")
    return f"vless://{user.uuid}@{_host(node)}:{node.port}?{urlencode(params, quote_via=quote)}#{label}"


def node_links(node: Node, user: User) -> dict[str, str]:
    return {"vision": vision_link(node, user), "xhttp": xhttp_link(node, user)}


def user_links(nodes: list[Node], user: User) -> list[str]:
    links = []
    for node in nodes:
        links += node_links(node, user).values()
    return links


def subscription(nodes: list[Node], user: User) -> str:
    """Standard v2ray-style subscription body: base64 of newline-separated links."""
    return base64.b64encode("\n".join(user_links(nodes, user)).encode()).decode()


def subscription_url(hub: Hub, user: User) -> str:
    return f"https://{hub.domain}/s/{user.sub_token}"


def vless_outbound(node: Node, uuid: str, transport: str, tag: str | None = None) -> dict:
    """Xray client outbound for one node and transport."""
    r = node.reality
    stream = {
        "security": "reality",
        "realitySettings": {
            "serverName": r.sni,
            "fingerprint": r.fingerprint,
            "password": r.public_key,
            "shortId": r.short_ids[0],
        },
    }
    user_entry = {"id": uuid, "encryption": "none"}
    if transport == "vision":
        stream["network"] = "raw"
        user_entry["flow"] = VISION_FLOW
    elif transport == "xhttp":
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = {"path": node.xhttp_path, "mode": "auto"}
    else:
        raise ValueError(f"unknown transport {transport!r}")
    outbound = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": node.host, "port": node.port, "users": [user_entry]}]},
        "streamSettings": stream,
    }
    if tag:
        outbound["tag"] = tag
    return outbound


def client_xray_config(node: Node, user: User, transport: str, socks_port: int) -> dict:
    """Minimal Xray client config (SOCKS in, one VLESS out). Used for smoke tests and
    for headless Linux clients; GUI clients should import share links instead."""
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [vless_outbound(node, user.uuid, transport)],
    }
