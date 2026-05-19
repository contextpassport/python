"""
v1.x compatibility shim.

Records produced under spec v1.x used Python's default `json.dumps` with
`sort_keys=True, separators=(",",":")` and `ensure_ascii=True` as the
canonical-JSON algorithm. This shim reproduces that exact serialization so
that v2.x verifiers can still validate v1.x records without rewriting them.

Use `verify_chain` from the top-level module for mixed-version chains; it
dispatches per-record on `schema_version` and calls into this shim when
needed.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Optional


def _canonical_v1(payload: Any) -> str:
    """v1.x canonicalization: sorted keys, no whitespace, ASCII escaping."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def payload_hash(payload: Any) -> str:
    """SHA-256 of the v1.x-canonicalized payload."""
    return "sha256:" + hashlib.sha256(_canonical_v1(payload).encode()).hexdigest()


def integrity_hash(pay_hash: str, parent_integrity: Optional[str]) -> str:
    chain_input = pay_hash + (parent_integrity or "root")
    return "sha256:" + hashlib.sha256(chain_input.encode()).hexdigest()


def verify_chain(passports: Iterable[dict]) -> bool:
    """Verify a chain of v1.x passports using v1.x canonicalization."""
    prev: Optional[dict] = None
    for p in passports:
        pay_hash = payload_hash(p["payload"])
        parent_int = prev["integrity"]["integrity_hash"] if prev else None
        expected = integrity_hash(pay_hash, parent_int)
        if p["integrity"]["integrity_hash"] != expected:
            return False
        prev = p
    return True
