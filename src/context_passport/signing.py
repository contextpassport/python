"""
Optional Ed25519 signing support for Context Passport.

Implements SPEC.md §3.2.7. The signature is computed over the canonical bytes
of the envelope with the `signature.signature` field cleared. Adding a
signature converts a tamper-evident chain into a non-repudiable one — any
third party with the public key can verify the record without involving
the issuer.

Install:
    pip install "context-passport[signing]"
"""

from __future__ import annotations

import base64
import copy
from typing import Optional, Tuple

from .passport import _canonical as _canonical_jcs

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError as e:
    raise ImportError(
        "Signing requires the 'cryptography' package. "
        'Install with: pip install "context-passport[signing]"'
    ) from e


# ----- helpers -------------------------------------------------------------

def _canonical_bytes_for_signing(passport: dict) -> bytes:
    """
    Canonical bytes over which the signature is computed.

    Per SPEC.md §3.2.7: signature is computed over the canonical envelope with
    signature.signature cleared. We implement that by cloning the passport,
    blanking signature.signature, then JSON-serializing with sorted keys.
    """
    clone = copy.deepcopy(passport)
    if "signature" in clone:
        sig_block = dict(clone["signature"])
        sig_block["signature"] = ""
        clone["signature"] = sig_block
    return _canonical_jcs(clone).encode("utf-8")


def generate_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair for testing/dev use."""
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def public_key_to_base64(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def public_key_from_base64(b64: str) -> Ed25519PublicKey:
    raw = base64.b64decode(b64)
    return Ed25519PublicKey.from_public_bytes(raw)


# ----- signing / verification ---------------------------------------------

def sign_passport(
    passport: dict,
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    public_key: Optional[Ed25519PublicKey] = None,
) -> dict:
    """
    Return a copy of the passport with a `signature` block populated.

    The signature is Ed25519 over the canonical bytes of the envelope with
    `signature.signature` cleared.

    Parameters
    ----------
    passport : dict
        A Context Passport v1.0 object. Must already have its integrity hashes
        computed.
    private_key : Ed25519PrivateKey
        The signing key.
    key_id : str
        Stable identifier for this key (rotation-aware).
    public_key : Ed25519PublicKey, optional
        If provided, the public key is included in the signature block as
        base64. If omitted, the public key is derived from the private key
        and included.
    """
    if public_key is None:
        public_key = private_key.public_key()

    signed = copy.deepcopy(passport)
    signed["signature"] = {
        "algorithm":  "ed25519",
        "key_id":     key_id,
        "public_key": public_key_to_base64(public_key),
        "signature":  "",  # cleared before computing the signature
    }
    msg = _canonical_bytes_for_signing(signed)
    sig = private_key.sign(msg)
    signed["signature"]["signature"] = base64.b64encode(sig).decode("ascii")
    return signed


def verify_signature(passport: dict, public_key: Optional[Ed25519PublicKey] = None) -> bool:
    """
    Verify the Ed25519 signature on a passport.

    If `public_key` is None, the public key embedded in passport.signature.public_key
    is used.

    Returns True if the signature is valid, False otherwise.
    """
    sig_block = passport.get("signature")
    if not sig_block:
        return False
    if sig_block.get("algorithm") != "ed25519":
        return False

    sig_b64 = sig_block.get("signature")
    if not sig_b64:
        return False

    if public_key is None:
        pub_b64 = sig_block.get("public_key")
        if not pub_b64:
            return False
        public_key = public_key_from_base64(pub_b64)

    msg = _canonical_bytes_for_signing(passport)
    try:
        public_key.verify(base64.b64decode(sig_b64), msg)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
