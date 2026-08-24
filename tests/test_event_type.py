import pytest
from context_passport.passport import make_passport

VALID = [
    "commit",
    "message",
    "tool_call",
    "tool_result",
    "plan",
    "observation",
    "decision",
    "error",
    "handoff",
    "fork",
    "merge",
    "rollback",
    "checkpoint",
    "resume",
    "custom",
    "acme.risk_review",
]

@pytest.mark.parametrize("event_type", VALID)
def test_valid_event_types(event_type):
    p = make_passport("a", "n", {"k": 1}, event_type=event_type)
    assert p["event"]["type"] == event_type

@pytest.mark.parametrize("event_type", [
    "",
    "Not A Type",
    ".leading_dot",
    "trailing.",
    "UPPER",
    "9start",
    "commit\n",
])
def test_invalid_event_types(event_type):
    with pytest.raises(ValueError) as ei:
        make_passport("a", "n", {"k": 1}, event_type=event_type)
    msg = str(ei.value)
    assert repr(event_type) in msg or event_type in msg
