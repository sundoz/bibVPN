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
ROLES = ("exit",)

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


@dataclass
class User:
    name: str
    uuid: str
    created: str
    enabled: bool = True
    note: str = ""


@dataclass
class State:
    nodes: list[Node] = field(default_factory=list)
    users: list[User] = field(default_factory=list)
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

    def add_node(self, name: str, host: str, sni: str, **kwargs) -> Node:
        check_name("node", name)
        if any(n.name == name for n in self.nodes):
            raise StateError(f"node {name} already exists")
        private_key, public_key = keys.reality_keypair()
        node = Node(
            name=name,
            host=host.strip().lower(),
            reality=Reality(
                sni=sni.strip().lower(),
                private_key=private_key,
                public_key=public_key,
                short_ids=[keys.short_id()],
            ),
            xhttp_path=keys.random_path(),
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

    def remove_user(self, name: str) -> None:
        self.users.remove(self.user(name))

    def rotate_node_keys(self, name: str) -> Node:
        """New Reality keys + short ID. Every client link for this node changes."""
        node = self.node(name)
        node.reality.private_key, node.reality.public_key = keys.reality_keypair()
        node.reality.short_ids = [keys.short_id()]
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
        for u in self.users:
            check_name("user", u.name)
            try:
                _require(str(uuidlib.UUID(u.uuid)) == u.uuid, f"user {u.name!r}: uuid must be lowercase canonical")
            except ValueError:
                raise StateError(f"user {u.name!r}: invalid uuid") from None

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
                nodes.append(Node(**raw))
            users = [User(**raw) for raw in data.get("users") or []]
        except (TypeError, KeyError, AttributeError) as e:
            raise StateError(f"malformed state file: {e}") from None
        state = cls(nodes=nodes, users=users, version=version)
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
    return State.from_dict(data)


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
