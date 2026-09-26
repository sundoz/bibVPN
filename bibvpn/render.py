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

from bibvpn import hub as hubmod
from bibvpn.links import subscription, subscription_url, user_links
from bibvpn.state import State
from bibvpn.xray import render_server_config


def render_inventory(state: State, build_dir: Path) -> dict:
    hosts = {}
    # Disabled nodes stay in the inventory: deploy must actively stop Xray there and
    # delete its config, or the server would keep accepting the old links.
    for node in state.nodes:
        host = {
            "ansible_host": node.host,
            "ansible_user": node.ssh_user,
            "ansible_port": node.ssh_port,
            "bibvpn_role": node.role,
            "bibvpn_node_enabled": node.enabled,
            "bibvpn_public_ports": [node.port] if node.enabled else [],
            "bibvpn_closed_ports": [] if node.enabled else [node.port],
        }
        if node.enabled:
            host["xray_config_src"] = str((build_dir / "nodes" / node.name / "config.json").resolve())
        hosts[node.name] = host
    groups = {"bibvpn_nodes": {"hosts": hosts}}
    if state.hub:
        hub_dir = (build_dir / "hub").resolve()
        groups["bibvpn_hub"] = {
            "hosts": {
                "hub": {
                    "ansible_host": state.hub.host,
                    "ansible_user": state.hub.ssh_user,
                    "ansible_port": state.hub.ssh_port,
                    "bibvpn_role": "hub",
                    # 80 is needed for the Let's Encrypt HTTP challenge.
                    "bibvpn_public_ports": [80, 443],
                    "hub_build_dir": str(hub_dir),
                    "hub_monitor_interval_min": state.monitor.interval_min,
                }
            }
        }
    return {"all": {"children": groups}}


def _write(path: Path, text: str, mode: int = 0o600) -> None:
    # Rendered files contain keys and UUIDs: owner-only, like the state file.
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, mode)


def render_all(state: State, build_dir: Path) -> list[Path]:
    build_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(build_dir, 0o700)
    # Start clean so removed nodes/users do not leave stale secrets behind.
    for sub in ("nodes", "clients", "hub"):
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
        if state.hub:
            url_path = build_dir / "clients" / f"{user.name}.url"
            _write(url_path, subscription_url(state.hub, user) + "\n")
            written.append(url_path)

    if state.hub:
        hub_dir = build_dir / "hub"
        files = {
            "probe-xray.json": json.dumps(hubmod.probe_xray_config(state), indent=2) + "\n",
            "monitor.json": json.dumps(hubmod.monitor_config(state), indent=2, ensure_ascii=False) + "\n",
            "Caddyfile": hubmod.caddyfile(state),
        }
        for name, text in files.items():
            _write(hub_dir / name, text)
            written.append(hub_dir / name)

    inv_path = build_dir / "inventory.yml"
    _write(inv_path, yaml.safe_dump(render_inventory(state, build_dir), sort_keys=False))
    written.append(inv_path)
    return written
