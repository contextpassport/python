"""
Context Passport v2.0 — core passport construction and verification.

This module is the reference implementation referenced from SPEC.md Appendix A.
It is intentionally small and dependency-free for the Core conformance level.
The optional `signing` extra adds Ed25519 signature support.

v2.0 adopts RFC 8785 (JSON Canonicalization Scheme / JCS) as the canonical
serialization for hashing and signing. See proposals/canonical-json-jcs.md
in the spec repo. For verifying v1.x records, use `context_passport.compat.v1`.
"""

from __future__ import annotations

import hashlib
import json
import math
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

SCHEMA_URL = "https://contextpassport.com/schema/v2.json"
SCHEMA_VERSION = "2.0"


def _normalize_number(n: float) -> Any:
    """JCS number normalization: reject non-finite, fold integer-valued floats to int,
    collapse negative zero."""
    if isinstance(n, bool):
        return n
    if math.isnan(n) or math.isinf(n):
        raise ValueError("JCS canonicalization does not permit NaN or Infinity")
    if n == 0:
        return 0
    if n.is_integer():
        return int(n)
    return n


def _normalize(value: Any) -> Any:
    """Recursively normalize a JSON-shaped value for JCS serialization."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return _normalize_number(value)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    raise TypeError(f"Value of type {type(value).__name__} is not JSON-serializable under JCS")


def _canonical(payload: Any) -> str:
    """RFC 8785 (JCS) canonical JSON serialization.

    - Keys sorted lexicographically (Python sorts by code point; equivalent to
      JCS UTF-16 code unit order for the BMP, which covers all common keys).
    - No whitespace.
    - ensure_ascii=False: raw UTF-8 emission for non-ASCII characters.
    - Numbers: integer-valued floats folded to ints, NaN/Infinity rejected.
    """
    normalized = _normalize(payload)
    return json.dumps(normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def payload_hash(payload: Any) -> str:
    """SHA-256 of the canonical (JCS) payload, formatted as `sha256:{hex}`."""
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def integrity_hash(pay_hash: str, parent_integrity: Optional[str]) -> str:
    """SHA-256 of payload_hash concatenated with parent integrity (or 'root')."""
    chain_input = pay_hash + (parent_integrity or "root")
    return "sha256:" + hashlib.sha256(chain_input.encode()).hexdigest()


def make_passport(
    agent_id: str,
    agent_name: str,
    payload: dict,
    *,
    parent: Optional[dict] = None,
    to_agent_id: Optional[str] = None,
    role: Optional[str] = None,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    event_type: str = "commit",
    trace_id: Optional[str] = None,
    branch_key: str = "main",
) -> dict:
    """Construct a v2.0 Context Passport."""
    ts = str(int(time.time() * 1000))
    hex_ = secrets.token_hex(6)
    ctx_id = f"ctx_{ts}_{hex_}"

    pay_hash = payload_hash(payload)
    if parent is not None:
        parent_int = parent["integrity"]["integrity_hash"]
        parent_id = parent["id"]
    else:
        parent_int = None
        parent_id = None

    int_hash = integrity_hash(pay_hash, parent_int)
    now = datetime.now(timezone.utc).isoformat()

    return {
        "$schema":        SCHEMA_URL,
        "schema_version": SCHEMA_VERSION,
        "id":             ctx_id,
        "parent_id":      parent_id,
        "trace_id":       trace_id,
        "branch_key":     branch_key,
        "created_by": {
            "agent_id":   agent_id,
            "agent_name": agent_name,
            "role":       role,
            "provider":   provider,
            "model":      model,
        },
        "event": {
            "type":        event_type,
            "to_agent_id": to_agent_id,
            "timestamp":   now,
        },
        "payload": payload,
        "integrity": {
            "payload_hash":        pay_hash,
            "parent_hash":         parent_int,
            "integrity_hash":      int_hash,
            "verification_status": "valid",
        },
        "lineage": {
            "fork_of":      None,
            "fork_point":   None,
            "lineage_root": None,
        },
        "created_at": now,
    }


def verify_chain(passports: Iterable[dict]) -> bool:
    """
    Verify that a sequence of passports forms an intact chain.

    Returns True if every integrity hash matches the recomputed value,
    False otherwise. Ignores unknown namespaced extension fields per spec.

    Dispatches per-record on schema_version: passports tagged "1.x" are
    verified using the v1 canonicalization shim; everything else uses v2 (JCS).
    """
    prev: Optional[dict] = None
    for p in passports:
        version = str(p.get("schema_version", "2.0"))
        if version.startswith("1."):
            from context_passport.compat import v1 as _v1
            pay_hash = _v1.payload_hash(p["payload"])
        else:
            pay_hash = payload_hash(p["payload"])
        parent_int = prev["integrity"]["integrity_hash"] if prev else None
        expected = integrity_hash(pay_hash, parent_int)
        if p["integrity"]["integrity_hash"] != expected:
            return False
        prev = p
    return True
