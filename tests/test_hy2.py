"""Hysteria2 (UDP) transport: certificates, config, links, firewall, monitoring."""

import json
import shutil
import subprocess

import pytest
import yaml
from cryptography import x509
from cryptography.x509.oid import NameOID

from bibvpn import cli, keys, links, monitor as mon, render, state as st
from bibvpn.xray import render_server_config


@pytest.fixture
def s():
    s = st.State()
    s.add_node("fi1", "203.0.113.5", sni="www.example.org")
    s.add_user("me")
    return s


def test_certificate_pin_and_key(s):
    h = s.node("fi1").hy2
    assert h.enabled and h.port == 443
    assert keys.cert_pin(h.cert_pem) == h.pin_sha256 and len(h.pin_sha256) == 64
    assert keys.cert_matches_key(h.cert_pem, h.key_pem)


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda h: setattr(h, "pin_sha256", "00" * 32), "pin_sha256"),
        (lambda h: setattr(h, "key_pem", keys.hy2_certificate("x.example")[1]), "key does not match"),
        (lambda h: setattr(h, "cert_pem", "not a certificate"), "bad hy2 certificate"),
        (lambda h: setattr(h, "port", 0), "hy2 port"),
    ],
)
def test_tampered_hy2_rejected(s, mutate, message):
    mutate(s.node("fi1").hy2)
    with pytest.raises(st.StateError, match=message):
        s.validate()


def test_sni_change_and_rotation_renew_certificate(s):
    old = s.node("fi1").hy2.pin_sha256
    s.rotate_node_keys("fi1")
    assert s.node("fi1").hy2.pin_sha256 != old


def test_old_nodes_get_a_certificate_once(tmp_path, s):
    path = tmp_path / "s.yml"
    data = s.to_dict()
    del data["nodes"][0]["hy2"]
    path.write_text(yaml.safe_dump(data))
    first, second = st.load(path), st.load(path)
    assert first.node("fi1").hy2 is not None
    assert first.node("fi1").hy2.pin_sha256 == second.node("fi1").hy2.pin_sha256


def test_server_inbound(s):
    cfg = render_server_config(s, s.node("fi1"))
    hy2 = next(i for i in cfg["inbounds"] if i["protocol"] == "hysteria")
    assert hy2["listen"] == "::" and hy2["port"] == 443
    assert [c["auth"] for c in hy2["settings"]["clients"]] == [s.user("me").uuid]
    stream = hy2["streamSettings"]
    assert stream["hysteriaSettings"]["masquerade"]["url"] == "https://www.example.org/"
    assert stream["tlsSettings"]["alpn"] == ["h3"]


def test_disabled_hy2_has_no_inbound_link_or_check(s):
    s.node("fi1").hy2.enabled = False
    assert all(i["protocol"] != "hysteria" for i in render_server_config(s, s.node("fi1"))["inbounds"])
    assert not any(link.startswith("hysteria2://") for link in links.user_links(s.nodes, s.user("me")))


def test_client_outbound_pins_certificate(s):
    o = links.client_outbound(s.node("fi1"), "u", "hy2", tag="t")
    assert o["tag"] == "t" and o["protocol"] == "hysteria"
    tls = o["streamSettings"]["tlsSettings"]
    assert tls["pinnedPeerCertSha256"] == s.node("fi1").hy2.pin_sha256
    assert "allowInsecure" not in tls


@pytest.mark.skipif(not shutil.which("xray"), reason="xray binary not on PATH")
def test_configs_accepted_by_xray(s):
    for cfg in (render_server_config(s, s.node("fi1")), links.client_xray_config(s.node("fi1"), s.user("me"), "hy2", 1080)):
        out = subprocess.run(["xray", "run", "-test", "-config", "stdin:"], input=json.dumps(cfg),
                             capture_output=True, text=True)
        assert out.returncode == 0, out.stdout + out.stderr


def test_firewall_ports(tmp_path, s):
    s.add_node("nl1", "203.0.113.6", sni="www.example.net", hy2=False)
    s.add_node("de1", "203.0.113.7", sni="www.example.com")
    s.node("de1").enabled = False
    render.render_all(s, tmp_path)
    hosts = yaml.safe_load((tmp_path / "inventory.yml").read_text())["all"]["children"]["bibvpn_nodes"]["hosts"]
    assert (hosts["fi1"]["bibvpn_public_udp_ports"], hosts["fi1"]["bibvpn_closed_udp_ports"]) == ([443], [])
    assert (hosts["nl1"]["bibvpn_public_udp_ports"], hosts["nl1"]["bibvpn_closed_udp_ports"]) == ([], [443])
    assert (hosts["de1"]["bibvpn_public_udp_ports"], hosts["de1"]["bibvpn_closed_udp_ports"]) == ([], [443])
    assert s.node("fi1").hy2.key_pem.splitlines()[1] not in (tmp_path / "inventory.yml").read_text()


def test_monitor_skips_tcp_check_for_udp():
    calls = []
    cfg = {"small_url": "https://s.example/", "large_url": "https://l.example/", "large_min_bytes": 1000}

    def tcp(host, port):
        calls.append(port)
        return None

    def curl(args, stdin=None, timeout=60):
        return (0, "204 0.1") if "https://s.example/" in args else (0, "4000 1000.0")

    check = {"host": "h", "port": 443, "socks_port": 1, "udp": True}
    assert mon.probe(check, cfg, tcp=tcp, curl=curl)["status"] == mon.OK and calls == []
    assert mon.probe({**check, "udp": False}, cfg, tcp=tcp, curl=curl)["status"] == mon.UNREACHABLE


def test_cli_flags(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "s.yml"
    run = lambda *a: cli.main(["--state", str(path), *a])  # noqa: E731
    run("init")
    run("node", "add", "fi1", "203.0.113.5", "--sni", "www.example.org", "--force", "--no-hy2")
    assert st.load(path).node("fi1").hy2.enabled is False
    run("node", "set", "fi1", "--hy2")
    assert st.load(path).node("fi1").hy2.enabled is True
    pin = st.load(path).node("fi1").hy2.pin_sha256
    run("node", "set", "fi1", "--sni", "www.example.net")
    node = st.load(path).node("fi1")
    assert node.hy2.pin_sha256 != pin, "SNI change must renew the certificate"
    cert = x509.load_pem_x509_certificate(node.hy2.cert_pem.encode())
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "www.example.net"
    capsys.readouterr()
    run("node", "list")
    assert "hy2=udp/443" in capsys.readouterr().out
