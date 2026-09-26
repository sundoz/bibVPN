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
