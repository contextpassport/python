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
