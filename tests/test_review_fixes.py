"""Regression tests for the external review findings."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from bibvpn import cli, render, state as st
from bibvpn.xray import PUBLIC_LISTEN, render_server_config

ROLES = Path(__file__).resolve().parent.parent / "ansible" / "roles"
SECRET_FILES = ("config.json", "probe-xray.json", "monitor.json")


def _tasks():
    for path in ROLES.glob("*/tasks/*.yml"):
        for task in yaml.safe_load(path.read_text()) or []:
            yield path, task
            for inner in task.get("block", []):
                yield path, inner


# --- 1. deploy --check --diff must not print secrets -------------------------


def test_secret_files_never_diffed():
    offenders = []
    for path, task in _tasks():
        for module in ("ansible.builtin.copy", "ansible.builtin.template"):
            args = task.get(module)
            if not isinstance(args, dict):
                continue
            touched = f"{args.get('src', '')} {args.get('dest', '')}"
            if any(name in touched for name in SECRET_FILES) and task.get("diff") is not False:
                offenders.append(f"{path.name}: {task['name']}")
    assert offenders == [], f"secret files copied with diff enabled: {offenders}"


def test_secrets_not_passed_as_task_arguments():
    # Module arguments show up in -v output and failure messages; secrets travel as files.
    for path, task in _tasks():
        cmd = task.get("ansible.builtin.command")
        if isinstance(cmd, dict):
            assert "stdin" not in cmd, f"{path.name}: {task['name']} passes data via stdin"
        text = json.dumps(task)
        assert "lookup('ansible.builtin.file'" not in text, f"{path.name}: {task['name']} inlines a file"


def test_every_secret_file_task_found():
    names = [t["name"] for _, t in _tasks() if any(f in json.dumps(t) for f in SECRET_FILES)]
    assert len(names) >= 5, names  # the static checks above actually see the tasks


# --- 2. disabling a node must stop it ------------------------------------------


@pytest.fixture
def s():
    s = st.State()
    s.add_node("fi1", "203.0.113.5", sni="www.example.org")
    s.add_node("nl1", "203.0.113.6", sni="www.example.net")
    s.add_user("me")
    return s


def test_disabled_node_stays_in_inventory_to_be_stopped(tmp_path, s):
    s.node("nl1").enabled = False
    render.render_all(s, tmp_path)
    hosts = yaml.safe_load((tmp_path / "inventory.yml").read_text())["all"]["children"]["bibvpn_nodes"]["hosts"]
    assert hosts["fi1"]["bibvpn_node_enabled"] is True and hosts["fi1"]["bibvpn_public_ports"] == [443]
    nl1 = hosts["nl1"]
    assert nl1["bibvpn_node_enabled"] is False
    assert nl1["bibvpn_public_ports"] == [] and nl1["bibvpn_closed_ports"] == [443]
    assert "xray_config_src" not in nl1
    assert not (tmp_path / "nodes" / "nl1").exists(), "no config (with keys) rendered for a disabled node"


def test_xray_role_handles_disabled_nodes():
    main = (ROLES / "xray" / "tasks" / "main.yml").read_text()
    disabled = yaml.safe_load((ROLES / "xray" / "tasks" / "disabled.yml").read_text())
    assert main.index("bibvpn_node_enabled") < main.index("xray_bin"), "must run before anything else"
    stop = next(t for t in disabled if "ansible.builtin.systemd" in t)["ansible.builtin.systemd"]
    assert stop["state"] == "stopped" and stop["enabled"] is False
    removed = next(t for t in disabled if "ansible.builtin.file" in t)
    assert removed["ansible.builtin.file"]["state"] == "absent"


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "s.yml"

    def _run(*argv):
        return cli.main(["--state", str(path), *argv])

    _run("init")
    _run("node", "add", "fi1", "203.0.113.5", "--sni", "www.example.org", "--force")
    _run.path = path
    return _run


def test_rm_refuses_running_node(run, capsys):
    assert run("node", "rm", "fi1") == 1
    assert "--disable" in capsys.readouterr().out
    assert st.load(run.path).nodes


def test_rm_after_disable(run):
    run("node", "set", "fi1", "--disable")
    assert run("node", "rm", "fi1") == 0
    assert st.load(run.path).nodes == []


def test_rm_force(run):
    assert run("node", "rm", "fi1", "--force") == 0


def test_disable_explains_effect(run, capsys):
    run("node", "set", "fi1", "--disable")
    assert "stopped" in capsys.readouterr().out


# --- 3. IPv6 nodes must actually listen on IPv6 ---------------------------------


@pytest.mark.parametrize("host", ["203.0.113.5", "2001:db8::1", "vpn.example.org"])
def test_public_listener_is_dual_stack(host):
    s = st.State()
    node = s.add_node("n1", host, sni="www.example.org")
    assert render_server_config(s, node)["inbounds"][0]["listen"] == PUBLIC_LISTEN == "::"


@pytest.mark.skipif(not shutil.which("xray"), reason="xray binary not on PATH")
def test_dual_stack_config_accepted_by_xray():
    s = st.State()
    node = s.add_node("v6", "2001:db8::1", sni="www.example.org")
    s.add_user("me")
    out = subprocess.run(["xray", "run", "-test", "-config", "stdin:"], input=json.dumps(render_server_config(s, node)),
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr


# --- 4. deploy --check must work on a fresh server -------------------------------


def test_tasks_needing_real_run_are_skipped_in_check_mode():
    """Tasks that use something created earlier in the same run (binary, unit,
    staged file) cannot work under --check, where nothing is written."""
    needs_real_run = []
    for path, task in _tasks():
        text = json.dumps(task)
        uses_new_things = (
            "xray_release_dir }}/xray run" in text
            or ".staged.json" in text and "remote_src" in text
            or task.get("ansible.builtin.systemd") is not None
            or task.get("ansible.builtin.wait_for") is not None
            or "unarchive" in text
        )
        if uses_new_things and "not ansible_check_mode" not in str(task.get("when", "")) and path.name != "disabled.yml":
            needs_real_run.append(f"{path.parent.parent.name}/{path.name}: {task['name']}")
    assert needs_real_run == []
