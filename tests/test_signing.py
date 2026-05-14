"""Tests for the optional Ed25519 signing module."""

from __future__ import annotations

import copy

import pytest

# Skip the entire module gracefully if cryptography is not installed.
pytest.importorskip("cryptography")

from context_passport import make_passport
from context_passport.signing import (
    generate_keypair,
    sign_passport,
    verify_signature,
    public_key_from_base64,
    public_key_to_base64,
)


def test_sign_and_verify_roundtrip():
    private, public = generate_keypair()
    p = make_passport(
        agent_id="a1", agent_name="Agent",
        payload={"input": "hello", "output": "world"},
    )
    signed = sign_passport(p, private, key_id="key-1")
    assert "signature" in signed
    assert signed["signature"]["algorithm"] == "ed25519"
    assert signed["signature"]["key_id"] == "key-1"
    assert signed["signature"]["signature"]
    assert verify_signature(signed) is True


def test_tampering_payload_breaks_signature():
    private, _ = generate_keypair()
    p = make_passport(
        agent_id="a1", agent_name="Agent",
        payload={"input": "hello", "output": "world"},
    )
    signed = sign_passport(p, private, key_id="key-1")
    # Tamper with the payload after signing
    tampered = copy.deepcopy(signed)
    tampered["payload"]["output"] = "TAMPERED"
    assert verify_signature(tampered) is False


def test_tampering_signature_itself_fails():
    private, _ = generate_keypair()
    p = make_passport(
        agent_id="a1", agent_name="Agent",
        payload={"input": "hello", "output": "world"},
    )
    signed = sign_passport(p, private, key_id="key-1")
    tampered = copy.deepcopy(signed)
    # Flip one character in the base64 signature
    sig = tampered["signature"]["signature"]
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    tampered["signature"]["signature"] = flipped
    assert verify_signature(tampered) is False


def test_verify_with_external_public_key():
    """Verifier may pass the public key separately (not embedded)."""
    private, public = generate_keypair()
    p = make_passport(
        agent_id="a1", agent_name="Agent",
        payload={"input": "x", "output": "y"},
    )
    signed = sign_passport(p, private, key_id="key-1")
    assert verify_signature(signed, public_key=public) is True


def test_unsigned_passport_returns_false():
    p = make_passport(
        agent_id="a1", agent_name="Agent",
        payload={"input": "x", "output": "y"},
    )
    assert verify_signature(p) is False


def test_public_key_base64_roundtrip():
    _, public = generate_keypair()
    b64 = public_key_to_base64(public)
    restored = public_key_from_base64(b64)
    assert public_key_to_base64(restored) == b64
