"""
Context Passport v1.0 — core passport construction and verification.

This module is the reference implementation referenced from SPEC.md Appendix A.
It is intentionally small and dependency-free for the Core conformance level.
The optional `signing` extra adds Ed25519 signature support.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

SCHEMA_URL = "https://contextpassport.com/schema/v1.json"
SCHEMA_VERSION = "1.0"


def _canonical(payload: Any) -> str:
    """Canonical JSON serialization: sorted keys, no whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def payload_hash(payload: Any) -> str:
    """SHA-256 of the canonical payload, formatted as `sha256:{hex}`."""
    return "sha256:" + hashlib.sha256(_canonical(payload).encode()).hexdigest()


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
    """Construct a v1.0 Context Passport."""
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
    """
    prev: Optional[dict] = None
    for p in passports:
        pay_hash = payload_hash(p["payload"])
        parent_int = prev["integrity"]["integrity_hash"] if prev else None
        expected = integrity_hash(pay_hash, parent_int)
        if p["integrity"]["integrity_hash"] != expected:
            return False
        prev = p
    return True
