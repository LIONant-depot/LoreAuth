"""JWKS helpers from RSA public key."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64url_uint(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


def kid_from_public_numbers(n: int, e: int) -> str:
    """Stable kid: first 16 hex of sha256(n||e) bytes."""
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    digest = hashlib.sha256(n_bytes + e_bytes).hexdigest()
    return digest[:16]


def load_private_key(path: str | Path):
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def public_key_from_private(private_key) -> rsa.RSAPublicKey:
    pub = private_key.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError("expected RSA private key")
    return pub


def jwk_from_public_key(
    public_key: rsa.RSAPublicKey, kid: Optional[str] = None
) -> Dict[str, Any]:
    numbers = public_key.public_numbers()
    kid = kid or kid_from_public_numbers(numbers.n, numbers.e)
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def jwks_from_private_key_path(path: str | Path, kid: Optional[str] = None) -> Dict[str, Any]:
    private_key = load_private_key(path)
    public_key = public_key_from_private(private_key)
    return {"keys": [jwk_from_public_key(public_key, kid=kid)]}


def write_jwks(jwks: Dict[str, Any], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(jwks, indent=2) + "\n", encoding="utf-8")


def generate_rsa_keypair(private_path: str | Path, public_path: Optional[str | Path] = None):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pp = Path(private_path)
    pp.parent.mkdir(parents=True, exist_ok=True)
    pp.write_bytes(priv_pem)
    try:
        pp.chmod(0o600)
    except OSError:
        pass
    if public_path:
        Path(public_path).write_bytes(pub_pem)
    return private_key, jwks_from_private_key_path(pp)
