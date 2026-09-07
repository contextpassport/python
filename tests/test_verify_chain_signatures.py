"""verify_chain must consult the signature when a record carries one.

The hash chain binds only the payload and the parent link. Everything else in
the envelope, created_by, event, trace_id, can be rewritten on an unsigned
record and the chain still verifies. The signature covers the whole envelope,
so it is what binds those fields. Before this change verify_chain never looked
at it, so a signed record with a forged author returned True from the one
function every adopter calls first.
"""

from __future__ import annotations

import pytest

# The signing extra is optional. Skip rather than fail where it is absent.
pytest.importorskip("cryptography")

from context_passport import make_passport, verify_chain
from context_passport.signing import generate_keypair, sign_passport


def _signed_chain():
    private, _public = generate_keypair()
    first = sign_passport(
        make_passport(agent_id="agent-a", agent_name="Agent A",
                      payload={"input": "x", "output": "y"}),
        private, key_id="key-1",
    )
    second = sign_passport(
        make_passport(agent_id="agent-b", agent_name="Agent B",
                      payload={"input": "y", "output": "z"}, parent=first),
        private, key_id="key-1",
    )
    return [first, second]


def test_pristine_signed_chain_verifies():
    assert verify_chain(_signed_chain()) is True


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r["created_by"].__setitem__("agent_id", "attacker"),
        lambda r: r["event"].__setitem__("type", "override"),
        lambda r: r["event"].__setitem__("timestamp", "2025-01-01T00:00:00Z"),
        lambda r: r["event"].__setitem__("to_agent_id", "attacker"),
        lambda r: r.__setitem__("trace_id", "forged"),
    ],
    ids=["agent_id", "event.type", "timestamp", "to_agent_id", "trace_id"],
)
def test_envelope_forgery_on_signed_record_fails(mutate):
    chain = _signed_chain()
    mutate(chain[0])
    # Hash-only verification cannot see any of these fields. That is the gap
    # this test exists to pin down: the first assertion documents it, the
    # second proves the signature closes it.
    assert verify_chain(chain, check_signatures=False) is True
    assert verify_chain(chain) is False


def test_payload_forgery_fails_either_way():
    chain = _signed_chain()
    chain[0]["payload"]["output"] = "FORGED"
    assert verify_chain(chain, check_signatures=False) is False
    assert verify_chain(chain) is False


def test_unsigned_chain_behaviour_unchanged():
    first = make_passport(agent_id="a", agent_name="A", payload={"k": 1})
    second = make_passport(agent_id="b", agent_name="B", payload={"k": 2}, parent=first)
    assert verify_chain([first, second]) is True
    # No signature block, so there is nothing to check and hash-only behaviour
    # is preserved exactly. This also pins the remaining gap: an unsigned
    # record's envelope is still unbound. Closing that is the 3.0 RFC's job,
    # not this function's, and a "fix" that rejected unsigned chains here would
    # break every 2.0 adopter.
    first["created_by"]["agent_id"] = "attacker"
    assert verify_chain([first, second]) is True
