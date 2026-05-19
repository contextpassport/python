"""
Context Passport — Python reference implementation.

Specification: https://github.com/contextpassport/spec
License: Apache-2.0
"""

from .passport import (
    make_passport,
    verify_chain,
    payload_hash,
    integrity_hash,
    SCHEMA_URL,
    SCHEMA_VERSION,
)

__version__ = "1.0.1"

__all__ = [
    "make_passport",
    "verify_chain",
    "payload_hash",
    "integrity_hash",
    "SCHEMA_URL",
    "SCHEMA_VERSION",
    "__version__",
]


def __getattr__(name):
    """
    Lazy access to signing helpers so the base package doesn't pay the
    import cost (or hard-require the cryptography dependency) for callers
    that never sign passports.
    """
    if name in {"sign_passport", "verify_signature", "generate_keypair",
                "public_key_to_base64", "public_key_from_base64"}:
        from . import signing
        return getattr(signing, name)
    raise AttributeError(f"module 'context_passport' has no attribute {name!r}")
