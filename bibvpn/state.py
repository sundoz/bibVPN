"""Single source of truth: nodes, their Reality keys and users, stored in one YAML file.

The state file holds secrets (private keys, client UUIDs) and must never be committed;
`state/` is git-ignored. Everything else (server configs, Ansible inventory, client
links) is rendered from it and can be regenerated at any time.
"""

import datetime as dt
import os
import re
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from bibvpn import keys

SCHEMA_VERSION = 1
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

class StateError(Exception):
    pass


def check_name(kind: str, name: str) -> str:
    if not NAME_RE.fullmatch(name):
        raise StateError(f"{kind} name {name!r} must match {NAME_RE.pattern}")
    return name


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
            host=host,
            reality=Reality(
                sni=sni,
                private_key=private_key,
                public_key=public_key,
                short_ids=[keys.short_id()],
            ),
            xhttp_path=keys.random_path(),
            **kwargs,
        )
        self.nodes.append(node)
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

    # --- (de)serialisation ------------------------------------------------

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "State":
        version = data.get("version", SCHEMA_VERSION)
        if version != SCHEMA_VERSION:
            raise StateError(f"unsupported state schema version {version}")
        nodes = []
        for raw in data.get("nodes") or []:
            raw = dict(raw)
            raw["reality"] = Reality(**raw["reality"])
            nodes.append(Node(**raw))
        users = [User(**raw) for raw in data.get("users") or []]
        return cls(nodes=nodes, users=users, version=version)


def default_path() -> Path:
    return Path(os.environ.get("BIBVPN_STATE", "state/bibvpn.yml"))


def load(path: Path) -> State:
    if not path.exists():
        raise StateError(f"state file {path} not found; run `bibvpn init` first")
    with path.open() as f:
        return State.from_dict(yaml.safe_load(f) or {})


def save(state: State, path: Path) -> None:
    """Atomic write with 0600 permissions: a crash never leaves a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".bibvpn-", suffix=".yml")
    try:
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(state.to_dict(), f, sort_keys=False, allow_unicode=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
