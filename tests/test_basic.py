"""Basic conformance smoke tests for the Python reference implementation."""

from context_passport import make_passport, verify_chain, payload_hash


def test_root_passport_has_no_parent():
    p = make_passport(
        agent_id="a1",
        agent_name="Agent One",
        payload={"input": "hello", "output": "world"},
    )
    assert p["parent_id"] is None
    assert p["integrity"]["parent_hash"] is None
    assert p["schema_version"] == "1.0"


def test_chain_links_correctly():
    a = make_passport(
        agent_id="a1", agent_name="Agent One",
        payload={"input": "x", "output": "y"},
    )
    b = make_passport(
        agent_id="a2", agent_name="Agent Two",
        payload={"input": "y", "output": "z"},
        parent=a,
    )
    assert b["parent_id"] == a["id"]
    assert b["integrity"]["parent_hash"] == a["integrity"]["integrity_hash"]
    assert verify_chain([a, b])


def test_canonicalization_is_order_independent():
    h1 = payload_hash({"a": 1, "b": 2})
    h2 = payload_hash({"b": 2, "a": 1})
    assert h1 == h2


def test_tampered_payload_breaks_chain():
    a = make_passport(
        agent_id="a1", agent_name="Agent One",
        payload={"input": "x", "output": "y"},
    )
    b = make_passport(
        agent_id="a2", agent_name="Agent Two",
        payload={"input": "y", "output": "z"},
        parent=a,
    )
    # Tamper with b's payload after the fact
    b["payload"]["output"] = "TAMPERED"
    assert verify_chain([a, b]) is False
