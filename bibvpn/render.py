"""Render everything derived from the state into `build/`:

build/
  inventory.yml            Ansible inventory (hosts + per-node vars)
  nodes/<node>/config.json Xray server config
  clients/<user>.txt       share links, one per line
  clients/<user>.sub       base64 subscription body
"""

import json
import os
import shutil
from pathlib import Path

import yaml

from bibvpn.links import subscription, user_links
from bibvpn.state import State
from bibvpn.xray import render_server_config


def render_inventory(state: State, build_dir: Path) -> dict:
    hosts = {}
    for node in state.active_nodes():
        hosts[node.name] = {
            "ansible_host": node.host,
            "ansible_user": node.ssh_user,
            "ansible_port": node.ssh_port,
            "bibvpn_role": node.role,
            "xray_public_ports": [node.port],
            "xray_config_src": str((build_dir / "nodes" / node.name / "config.json").resolve()),
        }
    return {"all": {"children": {"bibvpn_nodes": {"hosts": hosts}}}}


def _write(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, mode)


def render_all(state: State, build_dir: Path) -> list[Path]:
    # Start clean so removed nodes/users do not leave stale secrets behind.
    for sub in ("nodes", "clients"):
        shutil.rmtree(build_dir / sub, ignore_errors=True)

    written = []
    for node in state.active_nodes():
        path = build_dir / "nodes" / node.name / "config.json"
        _write(path, json.dumps(render_server_config(state, node), indent=2) + "\n")
        written.append(path)

    nodes = state.active_nodes()
    for user in state.active_users():
        links_path = build_dir / "clients" / f"{user.name}.txt"
        _write(links_path, "\n".join(user_links(nodes, user)) + "\n")
        sub_path = build_dir / "clients" / f"{user.name}.sub"
        _write(sub_path, subscription(nodes, user) + "\n")
        written += [links_path, sub_path]

    inv_path = build_dir / "inventory.yml"
    _write(inv_path, yaml.safe_dump(render_inventory(state, build_dir), sort_keys=False))
    written.append(inv_path)
    return written
