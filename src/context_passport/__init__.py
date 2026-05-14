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

__version__ = "1.0.0a1"

__all__ = [
    "make_passport",
    "verify_chain",
    "payload_hash",
    "integrity_hash",
    "SCHEMA_URL",
    "SCHEMA_VERSION",
    "__version__",
]
