from __future__ import annotations

import pytest

from agent_aa.crypto import (
    generate_sm2_private_key,
    protocol_message,
    sign_sm2,
    sm3_hex,
    verify_sm2,
)
from agent_aa.errors import VerificationError


def test_sm3_official_abc_vector() -> None:
    assert sm3_hex(b"abc") == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"


def test_sm2_sign_verify_and_tamper() -> None:
    key = generate_sm2_private_key()
    message = protocol_message("TEST", b'{"a":1}')
    signature = sign_sm2(key, message)
    verify_sm2(key.public_key(), message, signature)
    with pytest.raises(VerificationError, match="signature"):
        verify_sm2(key.public_key(), message + b"x", signature)


def test_signature_is_asn1_der() -> None:
    key = generate_sm2_private_key()
    signature = sign_sm2(key, b"message")
    assert signature[0] == 0x30
    assert 68 <= len(signature) <= 72
