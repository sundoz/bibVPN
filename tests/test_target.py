"""check-target against real local TLS servers with controlled capabilities."""

import datetime as dt
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from bibvpn.target import check_target


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    """Self-signed certificate for `localhost`; the file doubles as the trusted CA."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    d = tmp_path_factory.mktemp("tls")
    (d / "cert.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (d / "key.pem").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return str(d / "cert.pem"), str(d / "key.pem")


def serve(cert, max_version=ssl.TLSVersion.TLSv1_3, alpn=("h2",)):
    """Start a one-shot TLS server on 127.0.0.1; returns its port."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*cert)
    ctx.maximum_version = max_version
    if alpn:
        ctx.set_alpn_protocols(list(alpn))
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def run():
        with listener:
            conn, _ = listener.accept()
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

    threading.Thread(target=run, daemon=True).start()
    return port


def test_good_target(cert):
    r = check_target("localhost", port=serve(cert), ca_file=cert[0])
    assert r.ok, r.problems
    assert r.tls_version == "TLSv1.3" and r.alpn == "h2"


def test_tls12_only_rejected(cert):
    r = check_target("localhost", port=serve(cert, max_version=ssl.TLSVersion.TLSv1_2), ca_file=cert[0])
    assert not r.ok
    assert "TLS 1.3" in r.problems[0]


def test_no_http2_rejected(cert):
    r = check_target("localhost", port=serve(cert, alpn=("http/1.1",)), ca_file=cert[0])
    assert not r.ok
    assert any("HTTP/2" in p for p in r.problems)


def test_untrusted_certificate_rejected(cert):
    # Without our CA the self-signed certificate must not be accepted.
    r = check_target("localhost", port=serve(cert))
    assert not r.ok
    assert "certificate" in r.problems[0]


def test_connection_refused():
    with socket.create_server(("127.0.0.1", 0)) as s:
        port = s.getsockname()[1]
    r = check_target("localhost", port=port, timeout=2)
    assert not r.ok and "cannot connect" in r.problems[0]


@pytest.mark.parametrize("host", ["www.microsoft.com", "apple.com", "cdn.github.com"])
def test_overused_targets_warned(host, monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    assert check_target(host).warnings
