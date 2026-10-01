"""Secret generation: Reality X25519 key pairs, short IDs, client UUIDs, paths,
Hysteria2 certificates."""

import base64
import datetime as dt
import hashlib
import secrets
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from cryptography.x509.oid import NameOID


def _b64url(raw: bytes) -> str:
    # Xray uses unpadded URL-safe base64 for Reality keys.
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def reality_keypair() -> tuple[str, str]:
    """Return (private_key, public_key) in the format `xray x25519` prints."""
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return _b64url(private_raw), public_key_from_private(_b64url(private_raw))


def public_key_from_private(private_key: str) -> str:
    raw = _b64url_decode(private_key)
    if len(raw) != 32:
        raise ValueError("Reality private key must decode to 32 bytes")
    public = X25519PrivateKey.from_private_bytes(raw).public_key()
    return _b64url(public.public_bytes(Encoding.Raw, PublicFormat.Raw))


def short_id(nbytes: int = 8) -> str:
    """Reality short ID: 0-16 hex chars. Full length makes probing harder."""
    return secrets.token_hex(nbytes)


def client_uuid() -> str:
    return str(uuid.uuid4())


def random_path() -> str:
    """Unguessable HTTP path for XHTTP so the endpoint is not trivially probeable."""
    return "/" + secrets.token_urlsafe(12).replace("-", "").replace("_", "")[:16]


def sub_token() -> str:
    """Secret part of a subscription URL (192 bits)."""
    return secrets.token_urlsafe(24)


def hy2_certificate(name: str, days: int = 3650) -> tuple[str, str, str]:
    """Self-signed ECDSA certificate for Hysteria2 (QUIC needs TLS).

    Clients do not trust it through a CA; they pin its SHA-256 instead, so no domain or
    Let's Encrypt is needed on the node. Returns (cert_pem, key_pem, sha256_hex).
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(Encoding.PEM).decode()
    key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    return cert_pem, key_pem, cert_pin(cert_pem)


def cert_pin(cert_pem: str) -> str:
    """SHA-256 of the DER certificate, hex: what clients pin (pinSHA256)."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def cert_matches_key(cert_pem: str, key_pem: str) -> bool:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    der = lambda k: k.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)  # noqa: E731
    return der(cert.public_key()) == der(key.public_key())
