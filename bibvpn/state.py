"""Single source of truth: nodes, their Reality keys and users, stored in one YAML file.

The state file holds secrets (private keys, client UUIDs) and must never be committed;
`state/` is git-ignored. Everything else (server configs, Ansible inventory, client
links) is rendered from it and can be regenerated at any time.
"""

import datetime as dt
import ipaddress
import os
import re
import tempfile
import uuid as uuidlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from bibvpn import keys

SCHEMA_VERSION = 1
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SSH_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SHORT_ID_RE = re.compile(r"^([0-9a-f]{2}){0,8}$")
XHTTP_PATH_RE = re.compile(r"^/[A-Za-z0-9]{1,64}$")
SUB_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")
TITLE_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,32}$")
URL_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/?&=%+-]*)?$")
TG_TOKEN_RE = re.compile(r"^[0-9]{5,}:[A-Za-z0-9_-]{30,}$")
TG_CHAT_RE = re.compile(r"^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$")
ROLES = ("exit",)
TLS_MODES = ("auto", "internal")

class StateError(Exception):
    pass


def check_name(kind: str, name: str) -> str:
    if not NAME_RE.fullmatch(name):
        raise StateError(f"{kind} name {name!r} must match {NAME_RE.pattern}")
    return name


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise StateError(message)


def _check_uuid(value: str, where: str) -> None:
    try:
        _require(str(uuidlib.UUID(value)) == value, f"{where}: uuid must be lowercase canonical")
    except (ValueError, TypeError, AttributeError):
        raise StateError(f"{where}: invalid uuid") from None


@dataclass
class Reality:
    # `sni` is the real foreign site Reality impersonates; unauthenticated probes are
    # proxied to `sni:443`, so the node looks exactly like that site to the censor.
    sni: str
    private_key: str
    public_key: str
    short_ids: list[str]
    fingerprint: str = "chrome"


@dataclass
class Hy2:
    """Hysteria2 (QUIC over UDP): the fallback for when TCP to the node is throttled.

    The certificate is self-signed; clients pin its SHA-256, so no domain is needed.
    Unauthenticated HTTP/3 probes are proxied to the Reality SNI site (masquerade).
    """

    cert_pem: str
    key_pem: str
    pin_sha256: str
    port: int = 443  # UDP; does not clash with TCP 443
    enabled: bool = True

    @classmethod
    def generate(cls, name: str, **kwargs) -> "Hy2":
        cert_pem, key_pem, pin = keys.hy2_certificate(name)
        return cls(cert_pem=cert_pem, key_pem=key_pem, pin_sha256=pin, **kwargs)


@dataclass
class Node:
    name: str
    host: str
    reality: Reality
    ssh_user: str = "root"
    ssh_port: int = 22
    # "exit" nodes send traffic to the internet. "relay" (a node inside Russia that
    # forwards to an exit node) is reserved for the whitelist-bypass stage.
    role: str = "exit"
    # Everything is served on one port; anything but 443 stands out to DPI.
    port: int = 443
    xhttp_path: str = "/"
    enabled: bool = True
    hy2: Hy2 | None = None

    def transports(self) -> tuple[str, ...]:
        return ("vision", "xhttp") + (("hy2",) if self.hy2 and self.hy2.enabled else ())


@dataclass
class User:
    name: str
    uuid: str
    created: str
    enabled: bool = True
    note: str = ""
    # Secret part of the personal subscription URL; rotate if the URL leaks.
    sub_token: str = field(default_factory=keys.sub_token)


@dataclass
class Hub:
    """Small server that must stay reachable from Russia (ideally a Russian VPS).

    It serves subscriptions over HTTPS, probes every node from inside Russia and
    sends alerts; later it becomes the relay for whitelist-mode networks.
    """

    host: str
    # Name for the HTTPS certificate. Without an own domain, <ip-with-dashes>.sslip.io.
    domain: str
    ssh_user: str = "root"
    ssh_port: int = 22
    # "auto": Let's Encrypt certificate. "internal": self-signed, for tests only.
    tls: str = "auto"
    sub_update_hours: int = 3
    sub_title: str = "bibVPN"


@dataclass
class Monitor:
    interval_min: int = 5
    # Consecutive failed rounds before an alert; filters out one-off glitches.
    fail_threshold: int = 2
    small_url: str = "https://www.gstatic.com/generate_204"
    # Downloading ~1 MB catches the "freeze after 16-20 KB" block, which a small
    # request would not notice.
    large_url: str = "https://speed.cloudflare.com/__down?bytes=1048576"
    large_min_bytes: int = 262144
    telegram_token: str = ""
    telegram_chat_id: str = ""
    telegram_api: str = "https://api.telegram.org"
    # Identity the hub uses to test nodes, so probes never consume a real user.
    uuid: str = field(default_factory=keys.client_uuid)


@dataclass
class State:
    nodes: list[Node] = field(default_factory=list)
    users: list[User] = field(default_factory=list)
    hub: Hub | None = None
    monitor: Monitor = field(default_factory=Monitor)
    version: int = SCHEMA_VERSION

    # --- lookup -----------------------------------------------------------

    def node(self, name: str) -> Node:
        for n in self.nodes:
            if n.name == name:
                return n
        raise StateError(f"no such node: {name}")

    def user(self, name: str) -> User:
        for u in self.users:
            if u.name == name:
                return u
        raise StateError(f"no such user: {name}")

    def active_nodes(self) -> list[Node]:
        return [n for n in self.nodes if n.enabled]

    def active_users(self) -> list[User]:
        return [u for u in self.users if u.enabled]

    # --- mutation ---------------------------------------------------------

    def add_node(self, name: str, host: str, sni: str, hy2: bool = True, **kwargs) -> Node:
        check_name("node", name)
        if any(n.name == name for n in self.nodes):
            raise StateError(f"node {name} already exists")
        sni = sni.strip().lower()
        # Checked before anything is generated from it (the hy2 certificate uses it).
        _require(bool(HOSTNAME_RE.fullmatch(sni)), f"node {name!r}: sni must be a hostname like www.example.org")
        private_key, public_key = keys.reality_keypair()
        node = Node(
            name=name,
            host=host.strip().lower(),
            reality=Reality(
                sni=sni,
                private_key=private_key,
                public_key=public_key,
                short_ids=[keys.short_id()],
            ),
            xhttp_path=keys.random_path(),
            hy2=Hy2.generate(sni, enabled=hy2),
            **kwargs,
        )
        self.nodes.append(node)
        try:
            self.validate()
        except StateError:
            self.nodes.remove(node)
            raise
        return node

    def add_user(self, name: str, note: str = "") -> User:
        check_name("user", name)
        if any(u.name == name for u in self.users):
            raise StateError(f"user {name} already exists")
        user = User(name=name, uuid=keys.client_uuid(), created=dt.date.today().isoformat(), note=note)
        self.users.append(user)
        return user

    def set_hub(self, host: str, domain: str | None = None, **kwargs) -> Hub:
        host = host.strip().lower()
        if domain is None:
            if not is_ip(host) or ":" in host:
                raise StateError("pass --domain: sslip.io names only work for IPv4 addresses")
            domain = host.replace(".", "-") + ".sslip.io"
        previous = self.hub
        self.hub = Hub(host=host, domain=domain.strip().lower(), **kwargs)
        try:
            self.validate()
        except StateError:
            self.hub = previous
            raise
        return self.hub

    def rotate_sub_token(self, name: str) -> User:
        user = self.user(name)
        user.sub_token = keys.sub_token()
        return user

    def remove_user(self, name: str) -> None:
        self.users.remove(self.user(name))

    def rotate_node_keys(self, name: str) -> Node:
        """New Reality keys + short ID. Every client link for this node changes."""
        node = self.node(name)
        node.reality.private_key, node.reality.public_key = keys.reality_keypair()
        node.reality.short_ids = [keys.short_id()]
        self.renew_hy2_cert(name)
        return node

    def renew_hy2_cert(self, name: str) -> Node:
        """New Hysteria2 certificate (its pin is in every hy2 link for this node)."""
        node = self.node(name)
        enabled = node.hy2.enabled if node.hy2 else True
        port = node.hy2.port if node.hy2 else 443
        node.hy2 = Hy2.generate(node.reality.sni, enabled=enabled, port=port)
        return node

    # --- validation ---------------------------------------------------------

    def validate(self) -> None:
        """Reject anything that could produce a broken or unsafe config.

        Values from the state end up in Xray JSON, share links and the Ansible
        inventory (where `{{ ... }}` would be evaluated as a template on the operator's
        machine), so every field is checked against a strict whitelist on save and load.
        """
        _require(len({n.name for n in self.nodes}) == len(self.nodes), "duplicate node names")
        _require(len({u.name for u in self.users}) == len(self.users), "duplicate user names")
        _require(len({u.uuid for u in self.users}) == len(self.users), "duplicate user UUIDs")
        for n in self.nodes:
            where = f"node {n.name!r}"
            check_name("node", n.name)
            _require(is_ip(n.host) or bool(HOSTNAME_RE.fullmatch(n.host)), f"{where}: host must be an IP or hostname")
            _require(bool(HOSTNAME_RE.fullmatch(n.reality.sni)), f"{where}: sni must be a hostname like www.example.org")
            _require(bool(SSH_USER_RE.fullmatch(n.ssh_user)), f"{where}: invalid ssh_user")
            for port in (n.ssh_port, n.port):
                _require(isinstance(port, int) and 1 <= port <= 65535, f"{where}: invalid port {port!r}")
            _require(n.role in ROLES, f"{where}: role must be one of {ROLES}")
            _require(bool(XHTTP_PATH_RE.fullmatch(n.xhttp_path)), f"{where}: invalid xhttp_path")
            _require(
                bool(n.reality.short_ids) and all(SHORT_ID_RE.fullmatch(sid) for sid in n.reality.short_ids),
                f"{where}: short_ids must be hex strings of even length up to 16",
            )
            try:
                derived = keys.public_key_from_private(n.reality.private_key)
            except ValueError as e:
                raise StateError(f"{where}: bad Reality private key: {e}") from None
            _require(derived == n.reality.public_key, f"{where}: Reality public key does not match private key")
            if n.hy2:
                h = n.hy2
                _require(isinstance(h.port, int) and 1 <= h.port <= 65535, f"{where}: invalid hy2 port")
                _require(isinstance(h.enabled, bool), f"{where}: hy2.enabled must be true/false")
                try:
                    pin_ok = keys.cert_pin(h.cert_pem) == h.pin_sha256
                    key_ok = keys.cert_matches_key(h.cert_pem, h.key_pem)
                except (ValueError, TypeError) as e:
                    raise StateError(f"{where}: bad hy2 certificate or key: {e}") from None
                _require(pin_ok, f"{where}: hy2 pin_sha256 does not match the certificate")
                _require(key_ok, f"{where}: hy2 key does not match the certificate")
        _require(len({u.sub_token for u in self.users}) == len(self.users), "duplicate subscription tokens")
        for u in self.users:
            check_name("user", u.name)
            _check_uuid(u.uuid, f"user {u.name!r}")
            _require(bool(SUB_TOKEN_RE.fullmatch(u.sub_token)), f"user {u.name!r}: invalid sub_token")
        if self.hub:
            h = self.hub
            _require(is_ip(h.host) or bool(HOSTNAME_RE.fullmatch(h.host)), "hub: host must be an IP or hostname")
            _require(bool(HOSTNAME_RE.fullmatch(h.domain)), "hub: domain must be a hostname")
            _require(bool(SSH_USER_RE.fullmatch(h.ssh_user)), "hub: invalid ssh_user")
            _require(isinstance(h.ssh_port, int) and 1 <= h.ssh_port <= 65535, "hub: invalid ssh_port")
            _require(h.tls in TLS_MODES, f"hub: tls must be one of {TLS_MODES}")
            _require(isinstance(h.sub_update_hours, int) and 1 <= h.sub_update_hours <= 168, "hub: sub_update_hours 1-168")
            _require(bool(TITLE_RE.fullmatch(h.sub_title)), "hub: sub_title may use letters, digits, space . _ -")
            _require(h.host not in {n.host for n in self.nodes}, "hub must be a separate server from the nodes")
        m = self.monitor
        _require(isinstance(m.interval_min, int) and 1 <= m.interval_min <= 60, "monitor: interval_min 1-60")
        _require(isinstance(m.fail_threshold, int) and 1 <= m.fail_threshold <= 10, "monitor: fail_threshold 1-10")
        _require(isinstance(m.large_min_bytes, int) and 1024 <= m.large_min_bytes <= 100_000_000, "monitor: large_min_bytes")
        for url in (m.small_url, m.large_url, m.telegram_api):
            _require(bool(URL_RE.fullmatch(url)), f"monitor: invalid URL {url!r}")
        _require(m.telegram_token == "" or bool(TG_TOKEN_RE.fullmatch(m.telegram_token)), "monitor: invalid telegram token")
        _require(m.telegram_chat_id == "" or bool(TG_CHAT_RE.fullmatch(m.telegram_chat_id)), "monitor: invalid chat id")
        _check_uuid(m.uuid, "monitor")
        _require(m.uuid not in {u.uuid for u in self.users}, "monitor uuid collides with a user")

    # --- (de)serialisation ------------------------------------------------

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "State":
        version = data.get("version", SCHEMA_VERSION)
        if version != SCHEMA_VERSION:
            raise StateError(f"unsupported state schema version {version}")
        try:
            nodes = []
            for raw in data.get("nodes") or []:
                raw = dict(raw)
                raw["reality"] = Reality(**raw["reality"])
                if raw.get("hy2"):
                    raw["hy2"] = Hy2(**raw["hy2"])
                nodes.append(Node(**raw))
            users = [User(**raw) for raw in data.get("users") or []]
            hub = Hub(**data["hub"]) if data.get("hub") else None
            monitor = Monitor(**(data.get("monitor") or {}))
        except (TypeError, KeyError, AttributeError) as e:
            raise StateError(f"malformed state file: {e}") from None
        state = cls(nodes=nodes, users=users, hub=hub, monitor=monitor, version=version)
        state.validate()
        return state


def default_path() -> Path:
    return Path(os.environ.get("BIBVPN_STATE", "state/bibvpn.yml"))


def load(path: Path) -> State:
    if not path.exists():
        raise StateError(f"state file {path} not found; run `bibvpn init` first")
    with path.open() as f:
        try:
            data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise StateError(f"{path} is not valid YAML: {e}") from None
    if not isinstance(data, dict):
        raise StateError(f"{path} is not a bibvpn state file")
    state = State.from_dict(data)
    # Nodes created before Hysteria2 existed get a certificate once.
    for raw, node in zip(data.get("nodes") or [], state.nodes):
        if "hy2" not in raw:
            node.hy2 = Hy2.generate(node.reality.sni)
    # Fields added after a file was written get generated defaults (subscription
    # tokens, monitor identity, hy2 certificates). Persist them now, or they would
    # change on every run.
    if _missing_fields(data):
        save(state, path)
    return state


def _missing_fields(data: dict) -> bool:
    if "monitor" not in data or "uuid" not in (data.get("monitor") or {}):
        return True
    if any("hy2" not in n for n in data.get("nodes") or []):
        return True
    return any("sub_token" not in u for u in data.get("users") or [])


def save(state: State, path: Path) -> None:
    """Validated, atomic write with 0600 permissions (directory 0700): a crash never
    leaves a half-written file and invalid data never reaches the disk."""
    state.validate()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".bibvpn-", suffix=".yml")
    try:
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(state.to_dict(), f, sort_keys=False, allow_unicode=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
