import pytest

from context_passport import make_passport


SPECIFIED_EVENT_TYPES = [
    "commit",
    "fork",
    "checkpoint",
    "revert",
    "branch",
    "merge",
    "spawn",
    "retry",
    "timeout",
    "error",
    "override",
    "consent",
    "escalate",
    "redact",
    "audit",
]


@pytest.mark.parametrize("event_type", [*SPECIFIED_EVENT_TYPES, "acme.risk_review"])
def test_valid_event_types(event_type):
    passport = make_passport("a", "Agent", {}, event_type=event_type)
    assert passport["event"]["type"] == event_type


@pytest.mark.parametrize(
    "event_type",
    ["", "Not A Type", ".leading_dot", "trailing.", "UPPER", "9start", "commit\n", ["commit"]],
)
def test_invalid_event_types(event_type):
    with pytest.raises(ValueError, match="event_type"):
        make_passport("a", "Agent", {}, event_type=event_type)
