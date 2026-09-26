"""Render the Xray server config for a node.

Both transports live on the single public port (443) behind one Reality identity, so
the node exposes nothing but what looks like a TLS 1.3 site:

* VLESS + Reality + RAW + xtls-rprx-vision: the fastest option and the primary one.
* VLESS + Reality + XHTTP: HTTP/2 request/response framing. It survives some cases
  where long-lived raw streams get throttled or cut, and is the transport that can
  later be moved behind a CDN. After the Reality handshake, anything that is not a
  VLESS header (i.e. the HTTP/2 preface of an XHTTP client) is handed via `fallbacks`
  to an internal XHTTP inbound on an abstract unix socket.
"""

from bibvpn.state import Node, State, User

API_LISTEN = "127.0.0.1:10085"
XHTTP_SOCKET = "@bibvpn-xhttp"
VISION_FLOW = "xtls-rprx-vision"


def _reality(node: Node) -> dict:
    r = node.reality
    return {
        "show": False,
        "target": f"{r.sni}:443",
        "xver": 0,
        "serverNames": [r.sni],
        "privateKey": r.private_key,
        "shortIds": r.short_ids,
    }


def _clients(users: list[User], flow: str | None) -> list[dict]:
    clients = []
    for u in users:
        client = {"id": u.uuid, "email": u.name, "level": 0}
        if flow:
            client["flow"] = flow
        clients.append(client)
    return clients


def _sniffing() -> dict:
    # routeOnly: use the sniffed domain for routing rules but connect to the original IP.
    return {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}


def render_server_config(state: State, node: Node) -> dict:
    users = state.active_users()
    return {
        # Access logs are off on purpose: we do not keep records of what users visit.
        "log": {"loglevel": "warning", "access": "none", "dnsLog": False},
        "api": {"tag": "api", "listen": API_LISTEN, "services": ["StatsService", "HandlerService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        },
        "inbounds": [
            {
                "tag": "vless-vision",
                "listen": "0.0.0.0",
                "port": node.port,
                "protocol": "vless",
                "settings": {
                    "clients": _clients(users, VISION_FLOW),
                    "decryption": "none",
                    "fallbacks": [{"dest": XHTTP_SOCKET, "xver": 0}],
                },
                "streamSettings": {"network": "raw", "security": "reality", "realitySettings": _reality(node)},
                "sniffing": _sniffing(),
            },
            {
                "tag": "vless-xhttp",
                "listen": XHTTP_SOCKET,
                "protocol": "vless",
                "settings": {"clients": _clients(users, None), "decryption": "none"},
                "streamSettings": {
                    "network": "xhttp",
                    "xhttpSettings": {"path": node.xhttp_path, "mode": "auto"},
                },
                "sniffing": _sniffing(),
            },
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "dns": {"servers": ["https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query", "localhost"]},
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                # Clients must not reach the server's own network or loopback services.
                {"ip": ["geoip:private"], "outboundTag": "block"},
                # Torrent traffic is the #1 source of hoster abuse complaints and bans.
                {"protocol": ["bittorrent"], "outboundTag": "block"},
            ],
        },
    }
