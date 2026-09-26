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

from bibvpn.state import Node, State, is_ip

API_LISTEN = "127.0.0.1:10085"
XHTTP_SOCKET = "@bibvpn-xhttp"
VISION_FLOW = "xtls-rprx-vision"

# Non-public address space. Listed explicitly rather than only via geoip:private so the
# protection does not depend on the contents of a downloaded geo database.
PRIVATE_NETS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
]
# Outbound mail: open proxies get abused for spam, and hosters ban for it.
BLOCKED_PORTS = "25,465,587"


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


MONITOR_EMAIL = "_monitor"


def _identities(state: State) -> list[tuple[str, str]]:
    """(email, uuid) of everyone allowed in: active users, plus the hub's probe."""
    ids = [(u.name, u.uuid) for u in state.active_users()]
    if state.hub:
        ids.append((MONITOR_EMAIL, state.monitor.uuid))
    return ids


def _clients(identities: list[tuple[str, str]], flow: str | None) -> list[dict]:
    clients = []
    for email, uuid in identities:
        client = {"id": uuid, "email": email, "level": 0}
        if flow:
            client["flow"] = flow
        clients.append(client)
    return clients


# "::" is dual-stack: Go sets IPV6_V6ONLY=0 itself, so IPv4 clients are accepted too,
# and on kernels with IPv6 disabled it falls back to IPv4 (verified). "0.0.0.0" would
# silently make IPv6 nodes unreachable.
PUBLIC_LISTEN = "::"


def _internal_ips(node: Node) -> list[str]:
    ips = ["geoip:private", *PRIVATE_NETS]
    if is_ip(node.host):
        ips.append(node.host)
    return ips


def _sniffing() -> dict:
    # routeOnly: use the sniffed domain for routing rules but connect to the original IP.
    return {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}


def render_server_config(state: State, node: Node) -> dict:
    users = _identities(state)
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
                "listen": PUBLIC_LISTEN,
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
                # Clients must not reach the server's own services (SSH, the Xray API,
                # anything bound to localhost or the LAN, cloud metadata at 169.254.169.254).
                # Connections to the node's own public IP would arrive via loopback and skip
                # the firewall, so that IP is blocked too.
                {"ip": _internal_ips(node), "outboundTag": "block"},
                {"port": BLOCKED_PORTS, "outboundTag": "block"},
                # Torrent traffic is the #1 source of hoster abuse complaints and bans.
                {"protocol": ["bittorrent"], "outboundTag": "block"},
            ],
        },
    }
