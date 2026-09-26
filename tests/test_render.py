import base64
import json
import shutil
import subprocess
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml

from bibvpn import links, render, state as st
from bibvpn.xray import VISION_FLOW, XHTTP_SOCKET, render_server_config


@pytest.fixture
def s():
    s = st.State()
    s.add_node("fi1", "198.51.100.7", sni="www.example.org")
    s.add_user("me")
    s.add_user("mom")
    s.add_user("old").enabled = False
    return s


def test_server_config_single_port_with_xhttp_fallback(s):
    cfg = render_server_config(s, s.node("fi1"))
    vision, xhttp = cfg["inbounds"]
    assert vision["port"] == 443
    assert vision["settings"]["fallbacks"] == [{"dest": XHTTP_SOCKET, "xver": 0}]
    assert vision["streamSettings"]["realitySettings"]["target"] == "www.example.org:443"
    assert xhttp["listen"] == XHTTP_SOCKET and "port" not in xhttp
    assert xhttp["streamSettings"]["xhttpSettings"]["path"] == s.node("fi1").xhttp_path


def test_disabled_users_are_not_in_config(s):
    cfg = render_server_config(s, s.node("fi1"))
    for inbound in cfg["inbounds"]:
        emails = [c["email"] for c in inbound["settings"]["clients"]]
        assert emails == ["me", "mom"]
    assert all(c["flow"] == VISION_FLOW for c in cfg["inbounds"][0]["settings"]["clients"])
    assert all("flow" not in c for c in cfg["inbounds"][1]["settings"]["clients"])


def test_no_access_log(s):
    assert render_server_config(s, s.node("fi1"))["log"]["access"] == "none"


def test_links(s):
    node, user = s.node("fi1"), s.user("me")
    vision, xhttp = links.user_links([node], user)
    for link in (vision, xhttp):
        u = urlsplit(link)
        assert u.scheme == "vless" and u.username == user.uuid
        assert u.hostname == "198.51.100.7" and u.port == 443
        q = parse_qs(u.query)
        assert q["security"] == ["reality"] and q["pbk"] == [node.reality.public_key]
        assert q["sni"] == ["www.example.org"] and q["sid"] == node.reality.short_ids
    assert parse_qs(urlsplit(vision).query)["flow"] == [VISION_FLOW]
    assert parse_qs(urlsplit(xhttp).query)["path"] == [node.xhttp_path]


def test_ipv6_host_is_bracketed():
    s = st.State()
    node = s.add_node("v6", "2001:db8::1", sni="a.example")
    assert "@[2001:db8::1]:443?" in links.vision_link(node, s.add_user("me"))


def test_subscription_decodes_to_links(s):
    body = links.subscription(s.active_nodes(), s.user("me"))
    assert base64.b64decode(body).decode().splitlines() == links.user_links(s.active_nodes(), s.user("me"))


def test_render_all(tmp_path, s):
    render.render_all(s, tmp_path)
    inv = yaml.safe_load((tmp_path / "inventory.yml").read_text())
    host = inv["all"]["children"]["bibvpn_nodes"]["hosts"]["fi1"]
    assert host["ansible_host"] == "198.51.100.7" and host["bibvpn_public_ports"] == [443]
    assert json.loads((tmp_path / "nodes/fi1/config.json").read_text())["inbounds"]
    assert (tmp_path / "clients/me.txt").exists()
    assert not (tmp_path / "clients/old.txt").exists()

    # Removing a user must also remove their previously rendered links.
    s.remove_user("mom")
    render.render_all(s, tmp_path)
    assert not (tmp_path / "clients/mom.txt").exists()


@pytest.mark.skipif(not shutil.which("xray"), reason="xray binary not on PATH")
def test_config_accepted_by_xray(s):
    cfg = json.dumps(render_server_config(s, s.node("fi1")))
    out = subprocess.run(["xray", "run", "-test", "-config", "stdin:"], input=cfg, capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
