import pytest

from bibvpn import cli, state as st


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state_path = tmp_path / "state" / "bibvpn.yml"

    def _run(*argv):
        return cli.main(["--state", str(state_path), *argv])

    _run.state_path = state_path
    return _run


def test_workflow(run, capsys):
    assert run("init") == 0
    assert run("node", "add", "fi1", "198.51.100.7", "--sni", "www.example.org", "--force") == 0
    assert run("user", "add", "me") == 0
    capsys.readouterr()
    assert run("links", "me") == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 2 and all(line.startswith("vless://") for line in out)
    assert run("user", "disable", "me") == 0
    assert st.load(run.state_path).user("me").enabled is False
    assert run("render") == 0


def test_errors_are_reported_not_raised(run, capsys):
    run("init")
    assert run("user", "rm", "ghost") == 2
    assert "no such user" in capsys.readouterr().err


def test_extra_args_only_for_deploy(run):
    run("init")
    with pytest.raises(SystemExit):
        run("user", "list", "--private-key", "x")


def test_node_add_refuses_bad_sni(run, monkeypatch, capsys):
    from bibvpn import target

    run("init")
    bad = target.TargetReport(host="x.example", ok=False, problems=["TLS 1.3 handshake failed"])
    monkeypatch.setattr(target, "check_target", lambda host: bad)
    assert run("node", "add", "fi1", "198.51.100.7", "--sni", "x.example") == 1
    assert "TLS 1.3" in capsys.readouterr().out
    assert st.load(run.state_path).nodes == []


def test_node_add_rejects_injection(run, capsys):
    run("init")
    assert run("node", "add", "fi1", "{{ lookup('pipe','id') }}", "--sni", "www.example.org", "--force") == 2
    assert "host must be" in capsys.readouterr().err


def test_deploy_runs_playbook(run, monkeypatch, tmp_path):
    run("init")
    run("node", "add", "fi1", "198.51.100.7", "--sni", "www.example.org", "--force")
    calls = []
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd, cwd: calls.append(cmd) or 0)
    monkeypatch.setattr(cli.shutil, "which", lambda name, path=None: "/usr/bin/ansible-playbook")
    assert run("deploy", "--limit", "fi1", "--check", "--private-key", "k") == 0
    cmd = calls[0]
    assert cmd[0] == "/usr/bin/ansible-playbook" and cmd[-2:] == ["--private-key", "k"]
    assert ["--limit", "fi1"] == cmd[cmd.index("--limit") : cmd.index("--limit") + 2]
    assert "--check" in cmd and (tmp_path / "build" / "inventory.yml").exists()


def test_deploy_without_nodes(run, capsys):
    run("init")
    assert run("deploy") == 1
    assert "no nodes" in capsys.readouterr().out


def test_deploy_still_runs_when_every_node_is_disabled(run, monkeypatch):
    """Disabling the last node must still reach the server, or it keeps running."""
    run("init")
    run("node", "add", "fi1", "198.51.100.7", "--sni", "www.example.org", "--force")
    run("node", "set", "fi1", "--disable")
    calls = []
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd, cwd: calls.append(cmd) or 0)
    monkeypatch.setattr(cli.shutil, "which", lambda name, path=None: "/usr/bin/ansible-playbook")
    assert run("deploy") == 0 and calls
