"""Thin, auditable wrappers around Tongsuo's SM2/SM3 implementation."""

from __future__ import annotations

import base64
import os
import stat
import warnings
from pathlib import Path
from typing import Any

from tongsuopy.crypto import hashes, serialization
from tongsuopy.crypto.asymciphers import ec
from tongsuopy.crypto.exceptions import InvalidSignature

from .errors import ProtocolError, VerificationError

SM2_USER_ID = b"1234567812345678"
PROTOCOL_PREFIX = b"AACRED\x00"
PROTOCOL_VERSION = b"v1"


def sm3(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SM3())
    digest.update(data)
    return digest.finalize()


def sm3_hex(data: bytes) -> str:
    return sm3(data).hex()


def protocol_message(purpose: str, canonical_payload: bytes) -> bytes:
    """Apply mandatory domain separation before SM2-with-SM3 signing."""

    try:
        purpose_bytes = purpose.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ProtocolError("INVALID_DOMAIN", "signature purpose must be ASCII") from exc
    if not purpose_bytes or b"\x00" in purpose_bytes:
        raise ProtocolError("INVALID_DOMAIN", "signature purpose is empty or contains NUL")
    return PROTOCOL_PREFIX + purpose_bytes + b"\x00" + PROTOCOL_VERSION + b"\x00" + canonical_payload


def generate_sm2_private_key() -> Any:
    return ec.generate_private_key(ec.SM2())


def private_key_to_pem(private_key: Any) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: Any) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_pem(data: bytes) -> Any:
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except Exception as exc:  # Tongsuo exposes backend-specific parse exceptions.
        raise ProtocolError("INVALID_PRIVATE_KEY", "unable to load SM2 private key") from exc
    if getattr(getattr(key, "curve", None), "name", None) != "SM2":
        raise ProtocolError("INVALID_PRIVATE_KEY", "key is not on the SM2 curve")
    return key


def load_public_key_pem(data: bytes | str) -> Any:
    raw = data.encode("ascii") if isinstance(data, str) else data
    try:
        key = serialization.load_pem_public_key(raw)
    except Exception as exc:
        raise ProtocolError("INVALID_PUBLIC_KEY", "unable to load SM2 public key") from exc
    if getattr(getattr(key, "curve", None), "name", None) != "SM2":
        raise ProtocolError("INVALID_PUBLIC_KEY", "key is not on the SM2 curve")
    return key


def sign_sm2(private_key: Any, message: bytes) -> bytes:
    """SM2-with-SM3 over raw message bytes, returned as ASN.1 DER (r,s)."""

    return private_key.sign(message, ec.ECDSA(hashes.SM3()))


def verify_sm2(public_key: Any, message: bytes, signature: bytes) -> None:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SM3()))
    except (InvalidSignature, ValueError) as exc:
        raise VerificationError("INVALID_SIGNATURE", "SM2 signature verification failed") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise VerificationError("INVALID_SIGNATURE_ENCODING", "invalid base64url signature") from exc


def save_private_key(path: Path, private_key: Any, *, overwrite: bool = False) -> None:
    """Persist a demo/development key with owner-only permissions."""

    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing private key: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, private_key_to_pem(private_key))
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)
    actual_mode = stat.S_IMODE(path.stat().st_mode)
    if actual_mode & 0o077:
        warnings.warn(
            f"filesystem did not enforce owner-only mode for private key {path} "
            f"(reported {actual_mode:o}); use a protected Linux filesystem or secret manager",
            RuntimeWarning,
            stacklevel=2,
        )
