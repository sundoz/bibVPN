"""Hub: state model, rendered probe/monitor/Caddy files, inventory."""

import json
import shutil
import subprocess

import pytest
import yaml

from bibvpn import hub, links, render, state as st
from bibvpn.xray import MONITOR_EMAIL, render_server_config


@pytest.fixture
def s():
    s = st.State()
    s.add_node("fi1", "203.0.113.5", sni="www.example.org")
    s.add_node("nl1", "203.0.113.6", sni="www.example.net")
    s.add_user("me")
    s.add_user("old").enabled = False
    s.set_hub("198.51.100.9")
    return s


# --- state ------------------------------------------------------------------------


def test_default_domain_is_sslip(s):
    assert s.hub.domain == "198-51-100-9.sslip.io"


def test_ipv6_hub_needs_domain():
    with pytest.raises(st.StateError, match="domain"):
        st.State().set_hub("2001:db8::1")
    assert st.State().set_hub("2001:db8::1", domain="hub.example.org").domain == "hub.example.org"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"domain": "hub.example.org {\n respond"},  # Caddyfile injection
        {"sub_title": 'x"\nheader X-Evil 1'},
        {"tls": "off"},
        {"sub_update_hours": 0},
        {"ssh_user": "root;id"},
    ],
)
def test_bad_hub_settings_rejected_and_state_kept(s, kwargs):
    before = s.hub
    with pytest.raises(st.StateError):
        s.set_hub("198.51.100.10", **kwargs)
    assert s.hub is before


def test_hub_cannot_be_a_node(s):
    with pytest.raises(st.StateError, match="separate"):
        s.set_hub("203.0.113.5")


@pytest.mark.parametrize(
    "field, value",
    [
        ("telegram_token", "not-a-token"),
        ("telegram_chat_id", "12; rm"),
        ("small_url", "file:///etc/passwd"),
        ("large_url", 'https://x.example/"; bad'),
        ("interval_min", 0),
        ("fail_threshold", 99),
    ],
)
def test_bad_monitor_settings_rejected(s, field, value):
    setattr(s.monitor, field, value)
    with pytest.raises(st.StateError):
        s.validate()


def test_sub_tokens_unique_and_rotatable(s):
    s.add_user("mom")
    assert s.user("me").sub_token != s.user("mom").sub_token
    old = s.user("me").sub_token
    s.rotate_sub_token("me")
    assert s.user("me").sub_token != old and len(s.user("me").sub_token) == 32


def test_old_state_file_is_migrated_once(tmp_path):
    """A state file written before subscriptions existed gets stable tokens."""
    path = tmp_path / "bibvpn.yml"
    s = st.State()
    s.add_user("me")
    data = s.to_dict()
    del data["users"][0]["sub_token"]
    del data["monitor"]
    path.write_text(yaml.safe_dump(data))
    first = st.load(path)
    second = st.load(path)
    assert first.user("me").sub_token == second.user("me").sub_token
    assert first.monitor.uuid == second.monitor.uuid


def test_state_roundtrip_with_hub(tmp_path, s):
    path = tmp_path / "bibvpn.yml"
    st.save(s, path)
    assert st.load(path) == s


# --- server side --------------------------------------------------------------------


def test_monitor_identity_only_with_hub(s):
    emails = [c["email"] for c in render_server_config(s, s.node("fi1"))["inbounds"][0]["settings"]["clients"]]
    assert emails == ["me", MONITOR_EMAIL]
    s.hub = None
    emails = [c["email"] for c in render_server_config(s, s.node("fi1"))["inbounds"][0]["settings"]["clients"]]
    assert emails == ["me"]


# --- hub files ----------------------------------------------------------------------


def test_probe_checks_cover_every_node_and_transport(s):
    checks = hub.probe_checks(s)
    assert [c["id"] for c in checks] == ["fi1/vision", "fi1/xhttp", "nl1/vision", "nl1/xhttp"]
    assert len({c["socks_port"] for c in checks}) == 4


def test_probe_config_routes_each_port_to_its_node(s):
    cfg = hub.probe_xray_config(s)
    assert all(i["listen"] == "127.0.0.1" for i in cfg["inbounds"])
    out = {o["tag"]: o for o in cfg["outbounds"]}
    for rule in cfg["routing"]["rules"][:-1]:
        o = out[rule["outboundTag"]]
        assert o["settings"]["vnext"][0]["users"][0]["id"] == s.monitor.uuid
    assert cfg["routing"]["rules"][-1]["outboundTag"] == "block"


@pytest.mark.skipif(not shutil.which("xray"), reason="xray binary not on PATH")
def test_probe_config_accepted_by_xray(s):
    out = subprocess.run(["xray", "run", "-test", "-config", "stdin:"], input=json.dumps(hub.probe_xray_config(s)),
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr


def test_monitor_config_excludes_disabled_users(s):
    cfg = hub.monitor_config(s)
    assert [x["user"] for x in cfg["subscriptions"]] == ["me"]
    sub = cfg["subscriptions"][0]
    assert sub["token"] == s.user("me").sub_token
    assert sub["links"]["fi1"] == links.node_links(s.node("fi1"), s.user("me"))


def test_caddyfile(s):
    text = hub.caddyfile(s)
    assert text.splitlines()[1] == "198-51-100-9.sslip.io {"
    assert "tls internal" not in text
    assert 'Profile-Title "base64:YmliVlBO"' in text
    assert "\tlog" not in text, "no access log: tokens are credentials"
    assert "handle_path /s/*" in text and "respond 404" in text
    s.hub.tls = "internal"
    assert "tls internal" in hub.caddyfile(s)


def test_subscription_url(s):
    assert links.subscription_url(s.hub, s.user("me")) == f"https://198-51-100-9.sslip.io/s/{s.user('me').sub_token}"


def test_render_hub(tmp_path, s):
    render.render_all(s, tmp_path)
    inv = yaml.safe_load((tmp_path / "inventory.yml").read_text())["all"]["children"]
    h = inv["bibvpn_hub"]["hosts"]["hub"]
    assert h["ansible_host"] == "198.51.100.9" and h["bibvpn_public_ports"] == [80, 443]
    assert s.monitor.uuid not in (tmp_path / "inventory.yml").read_text()
    for name in ("probe-xray.json", "monitor.json", "Caddyfile"):
        assert (tmp_path / "hub" / name).exists()
    assert (tmp_path / "clients" / "me.url").read_text().startswith("https://198-51-100-9.sslip.io/s/")

    s.hub = None
    render.render_all(s, tmp_path)
    assert not (tmp_path / "hub").exists(), "stale hub secrets are removed"
