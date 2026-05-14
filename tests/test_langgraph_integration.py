"""
Tests for the LangGraph integration.

These tests do not require LangGraph itself — they exercise the callback
handler directly with synthetic chain events, mirroring what LangGraph would
emit at runtime.
"""

from __future__ import annotations

import pytest

# Skip the entire module gracefully if langchain-core is not installed.
pytest.importorskip("langchain_core")

from uuid import uuid4
from context_passport import verify_chain
from context_passport.integrations.langgraph import LangGraphPassportCallback


def _fire_chain(handler, *, node_name, inputs, outputs):
    """Helper: simulate LangChain firing on_chain_start then on_chain_end."""
    run_id = uuid4()
    handler.on_chain_start(
        serialized={"name": node_name},
        inputs=inputs,
        run_id=run_id,
    )
    handler.on_chain_end(outputs=outputs, run_id=run_id)


def test_single_node_emits_one_passport():
    h = LangGraphPassportCallback(
        agent_id="agent-1",
        agent_name="Test Agent",
        provider="anthropic",
        model="claude-opus-4-6",
    )
    _fire_chain(h, node_name="planner", inputs={"q": "hello"}, outputs={"plan": "do x"})
    assert len(h.passports) == 1
    p = h.passports[0]
    assert p["event"]["type"] == "commit"
    assert p["created_by"]["agent_id"] == "agent-1"
    assert p["payload"]["memory"]["node"] == "planner"
    assert p["payload"]["input"] == {"q": "hello"}
    assert p["payload"]["output"] == {"plan": "do x"}
    assert p["parent_id"] is None


def test_two_nodes_produce_chained_passports():
    h = LangGraphPassportCallback(agent_id="agent-1", agent_name="Test Agent")
    _fire_chain(h, node_name="researcher", inputs={"q": "?"}, outputs={"facts": [1, 2]})
    _fire_chain(h, node_name="writer", inputs={"facts": [1, 2]}, outputs={"draft": "..."})

    assert len(h.passports) == 2
    a, b = h.passports
    assert a["parent_id"] is None
    assert b["parent_id"] == a["id"]
    assert b["integrity"]["parent_hash"] == a["integrity"]["integrity_hash"]
    assert verify_chain([a, b])


def test_commit_fn_is_called_per_passport():
    received = []
    h = LangGraphPassportCallback(
        agent_id="agent-1",
        agent_name="Test Agent",
        commit_fn=lambda p: received.append(p),
    )
    _fire_chain(h, node_name="a", inputs={"x": 1}, outputs={"y": 2})
    _fire_chain(h, node_name="b", inputs={"y": 2}, outputs={"z": 3})
    assert len(received) == 2
    assert received[0]["payload"]["memory"]["node"] == "a"
    assert received[1]["payload"]["memory"]["node"] == "b"


def test_chain_error_emits_error_event():
    h = LangGraphPassportCallback(agent_id="agent-1", agent_name="Test Agent")
    run_id = uuid4()
    h.on_chain_start(serialized={"name": "risky"}, inputs={"in": "bad"}, run_id=run_id)
    h.on_chain_error(error=ValueError("boom"), run_id=run_id)

    assert len(h.passports) == 1
    p = h.passports[0]
    assert p["event"]["type"] == "error"
    assert p["payload"]["memory"]["error_type"] == "ValueError"
    assert p["payload"]["memory"]["error_message"] == "boom"


def test_continues_from_external_parent():
    """A handler can be given a starting parent to extend an existing chain."""
    from context_passport import make_passport
    seed = make_passport(
        agent_id="upstream",
        agent_name="Upstream",
        payload={"input": "seed", "output": "ok"},
    )
    h = LangGraphPassportCallback(
        agent_id="agent-1",
        agent_name="Test Agent",
        parent=seed,
    )
    _fire_chain(h, node_name="first", inputs={"a": 1}, outputs={"b": 2})

    assert h.passports[0]["parent_id"] == seed["id"]
    assert verify_chain([seed] + h.passports)
