"""JCS (RFC 8785) canonicalization edge cases for v2.0."""

import pytest

from context_passport import payload_hash
from context_passport.passport import _canonical
from context_passport.compat import v1 as compat_v1


def test_non_ascii_emitted_raw():
    # JCS emits raw UTF-8, no \uXXXX escapes for printable non-ASCII.
    assert _canonical({"name": "François"}) == '{"name":"François"}'


def test_emoji_emitted_raw():
    assert _canonical({"msg": "hi 👋"}) == '{"msg":"hi 👋"}'


def test_integer_valued_float_folds_to_int():
    # 1.0 → 1 per ECMAScript ToString
    assert _canonical({"x": 1.0}) == '{"x":1}'


def test_negative_zero_collapses():
    assert _canonical({"x": -0.0}) == '{"x":0}'


def test_nan_rejected():
    with pytest.raises(ValueError):
        _canonical({"x": float("nan")})


def test_infinity_rejected():
    with pytest.raises(ValueError):
        _canonical({"x": float("inf")})


def test_large_integer_preserved():
    # Python ints are unbounded; JCS preserves them as-is in canonical form.
    assert _canonical({"id": 12345678901234567}) == '{"id":12345678901234567}'


def test_v1_compat_matches_legacy_behaviour():
    # Sanity: v1 shim still escapes non-ASCII (ensure_ascii=True default).
    h_v1 = compat_v1.payload_hash({"name": "François"})
    h_v2 = payload_hash({"name": "François"})
    assert h_v1 != h_v2  # v1 escapes; v2 emits raw → different bytes → different hash

def test_key_order_is_utf16_not_code_point():
    """RFC 8785 3.2.3 sorts keys by UTF-16 code unit, not code point.

    The two agree across the BMP and disagree above it. U+1F600 encodes to the
    surrogate pair D83D DE00, so it sorts below U+FF01 in UTF-16 and above it by
    code point. Python's sorted() and json.dumps(sort_keys=True) use code point,
    which is what this module used to do.

    The consequence was concrete: a payload with an emoji key hashed differently
    here than in @contextpassport/core, so a record written by one SDK failed
    verification in the other. No conformance vector contained an astral
    character, so nothing caught it.
    """
    payload = {"a": 1, "😀": "astral", "！": "bmp"}
    canonical = _canonical(payload)

    # The astral key must come first, ahead of the BMP one.
    assert canonical.index("😀") < canonical.index("！"), canonical

    # And the hash must equal what the TypeScript SDK produces for this payload.
    assert payload_hash(payload) == (
        "sha256:03b0961b449b0349890fbcb8ec62886006ded6272f75fcd92d2698af1ba7c297"
    ), payload_hash(payload)


def test_bmp_key_order_is_unchanged():
    """The fix must not move any key that was already ordered correctly."""
    payload = {"z": 1, "a": 2, "m": 3, "é": 4, "中": 5}
    assert _canonical(payload) == (
        '{"a":2,"m":3,"z":1,"é":4,"中":5}'
    ), _canonical(payload)
