"""Secret generation: Reality X25519 key pairs, short IDs, client UUIDs, paths."""

import base64
import secrets
import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


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
