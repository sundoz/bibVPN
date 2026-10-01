"""Security properties of the state, rendered configs and files on disk."""

import copy
import os
import stat

import pytest
import yaml

from bibvpn import keys, render, state as st
from bibvpn.xray import API_LISTEN, BLOCKED_PORTS, PRIVATE_NETS, render_server_config


@pytest.fixture
def s():
    s = st.State()
    s.add_node("fi1", "203.0.113.5", sni="www.example.org")
    s.add_user("me")
    return s


# --- input validation -------------------------------------------------------

INJECTIONS = [
    "{{ lookup('pipe', 'id') }}",  # Ansible template injection via the inventory
    "1.2.3.4 -o ProxyCommand=sh",  # ssh option injection
    "host\nansible_become_pass: x",  # YAML/inventory injection
    "a b.example",
    "",
]


@pytest.mark.parametrize("bad", INJECTIONS)
def test_malicious_host_rejected(bad):
    with pytest.raises(st.StateError):
        st.State().add_node("n1", bad, sni="www.example.org")


@pytest.mark.parametrize("bad", INJECTIONS + ["203.0.113.5", "localhost", "example"])
def test_malicious_or_bad_sni_rejected(bad):
    with pytest.raises(st.StateError):
        st.State().add_node("n1", "203.0.113.5", sni=bad)


@pytest.mark.parametrize("bad", ["root; rm -rf /", "Root", "-o", "a" * 40])
def test_bad_ssh_user_rejected(bad):
    with pytest.raises(st.StateError):
        st.State().add_node("n1", "203.0.113.5", sni="www.example.org", ssh_user=bad)


@pytest.mark.parametrize("port", [0, 65536, -1, "443"])
def test_bad_ports_rejected(port):
    with pytest.raises(st.StateError):
        st.State().add_node("n1", "203.0.113.5", sni="www.example.org", port=port)


def test_failed_add_node_leaves_state_unchanged():
    s = st.State()
    with pytest.raises(st.StateError):
        s.add_node("n1", "{{ x }}", sni="www.example.org")
    assert s.nodes == []


def test_host_and_sni_are_normalised():
    node = st.State().add_node("n1", " Node.Example.ORG ", sni="WWW.Example.org")
    assert node.host == "node.example.org" and node.reality.sni == "www.example.org"


def test_ipv6_host_accepted():
    assert st.State().add_node("n1", "2001:db8::1", sni="www.example.org").host == "2001:db8::1"


def _tampered(s, mutate):
    data = copy.deepcopy(s.to_dict())
    mutate(data)
    return data


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda d: d["nodes"][0].update(host="{{ lookup('pipe','id') }}"), "host"),
        (lambda d: d["nodes"][0]["reality"].update(public_key=keys.reality_keypair()[1]), "does not match"),
        (lambda d: d["nodes"][0]["reality"].update(private_key="short"), "private key"),
        (lambda d: d["nodes"][0]["reality"].update(short_ids=["xyz"]), "short_ids"),
        (lambda d: d["nodes"][0]["reality"].update(short_ids=[]), "short_ids"),
        (lambda d: d["nodes"][0].update(xhttp_path="/a/../b"), "xhttp_path"),
        (lambda d: d["nodes"][0].update(role="relay"), "role"),
        (lambda d: d["users"][0].update(uuid="not-a-uuid"), "uuid"),
        (lambda d: d["users"].append(dict(d["users"][0], name="copy")), "duplicate user UUIDs"),
        (lambda d: d["users"].append(dict(d["users"][0])), "duplicate user names"),
        (lambda d: d["nodes"][0].update(unexpected="x"), "malformed"),
        (lambda d: d.update(version=99), "schema version"),
    ],
)
def test_tampered_state_rejected_on_load(s, mutate, message):
    with pytest.raises(st.StateError, match=message):
        st.State.from_dict(_tampered(s, mutate))


def test_invalid_state_is_never_written(tmp_path, s):
    path = tmp_path / "bibvpn.yml"
    s.nodes[0].reality.sni = "{{ x }}"
    with pytest.raises(st.StateError):
        st.save(s, path)
    assert not path.exists()
    assert list(tmp_path.iterdir()) == []  # no temp file left behind


@pytest.mark.parametrize("content", ["just a string", "- a\n- list", "{bad yaml"])
def test_garbage_state_file(tmp_path, content):
    path = tmp_path / "bibvpn.yml"
    path.write_text(content)
    with pytest.raises(st.StateError):
        st.load(path)


def test_yaml_tags_are_not_executed(tmp_path):
    path = tmp_path / "bibvpn.yml"
    path.write_text("!!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(st.StateError):
        st.load(path)


# --- secrets on disk --------------------------------------------------------


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_state_file_and_dir_private(tmp_path, s):
    path = tmp_path / "state" / "bibvpn.yml"
    st.save(s, path)
    assert _mode(path) == 0o600
    assert _mode(path.parent) == 0o700


def test_rendered_files_private(tmp_path, s):
    build = tmp_path / "build"
    for path in render.render_all(s, build):
        assert _mode(path) == 0o600, path
        assert _mode(path.parent) == 0o700, path.parent
    assert _mode(build) == 0o700


def test_inventory_contains_no_secrets(tmp_path, s):
    render.render_all(s, tmp_path)
    text = (tmp_path / "inventory.yml").read_text()
    assert s.nodes[0].reality.private_key not in text
    assert s.users[0].uuid not in text
    yaml.safe_load(text)


# --- server config ----------------------------------------------------------


def test_internal_addresses_blocked(s):
    cfg = render_server_config(s, s.node("fi1"))
    rule = cfg["routing"]["rules"][0]
    assert rule["outboundTag"] == "block"
    for net in ("127.0.0.0/8", "169.254.0.0/16", "10.0.0.0/8", "::1/128", "fc00::/7"):
        assert net in rule["ip"] and net in PRIVATE_NETS
    assert "203.0.113.5" in rule["ip"], "node's own public IP must be blocked"


def test_own_ip_rule_skipped_for_hostname_nodes():
    s = st.State()
    node = s.add_node("n1", "vpn.example.org", sni="www.example.org")
    rule = render_server_config(s, node)["routing"]["rules"][0]
    assert "vpn.example.org" not in rule["ip"]


def test_abuse_blocking(s):
    rules = render_server_config(s, s.node("fi1"))["routing"]["rules"]
    assert {"port": BLOCKED_PORTS, "outboundTag": "block"} in rules
    assert {"protocol": ["bittorrent"], "outboundTag": "block"} in rules
    assert "25" in BLOCKED_PORTS.split(",")


def test_only_expected_public_listeners(s):
    cfg = render_server_config(s, s.node("fi1"))
    public = [i for i in cfg["inbounds"] if i["listen"] in ("0.0.0.0", "::")]
    # One TCP listener (Reality) and one UDP listener (Hysteria2), both on 443.
    assert [(i["protocol"], i["port"]) for i in public] == [("vless", 443), ("hysteria", 443)]
    assert public[0]["streamSettings"]["security"] == "reality"
    hy2 = public[1]["streamSettings"]
    assert hy2["security"] == "tls" and hy2["hysteriaSettings"]["masquerade"]["type"] == "proxy"


def test_api_is_loopback_only(s):
    cfg = render_server_config(s, s.node("fi1"))
    assert cfg["api"]["listen"] == API_LISTEN
    assert API_LISTEN.startswith("127.0.0.1:")


def test_reality_does_not_leak_debug_info(s):
    reality = render_server_config(s, s.node("fi1"))["inbounds"][0]["streamSettings"]["realitySettings"]
    assert reality["show"] is False
    assert all(len(sid) == 16 for sid in reality["shortIds"])


def test_no_logs_of_visited_sites(s):
    log = render_server_config(s, s.node("fi1"))["log"]
    assert log["access"] == "none" and log["dnsLog"] is False


def test_disabled_user_cannot_authenticate(s):
    s.user("me").enabled = False
    cfg = render_server_config(s, s.node("fi1"))
    assert all(not i["settings"]["clients"] for i in cfg["inbounds"])
