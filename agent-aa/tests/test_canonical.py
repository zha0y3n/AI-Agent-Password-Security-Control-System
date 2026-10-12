from __future__ import annotations

import pytest

from agent_aa.canonical import canonical_json, strict_json_loads
from agent_aa.errors import CanonicalizationError


def test_canonical_json_has_stable_key_order_and_utf8() -> None:
    left = canonical_json({"中文": "值", "a": 1, "nested": {"z": False, "b": None}})
    right = canonical_json({"nested": {"b": None, "z": False}, "a": 1, "中文": "值"})
    assert left == right
    assert left == b'{"a":1,"nested":{"b":null,"z":false},"\xe4\xb8\xad\xe6\x96\x87":"\xe5\x80\xbc"}'


@pytest.mark.parametrize("value", [1.0, float("nan"), float("inf")])
def test_canonical_json_rejects_floats(value: float) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json({"value": value})


def test_strict_json_rejects_duplicate_fields() -> None:
    with pytest.raises(CanonicalizationError, match="duplicate"):
        strict_json_loads(b'{"task_id":"a","task_id":"b"}')


def test_strict_json_rejects_out_of_range_integer() -> None:
    with pytest.raises(CanonicalizationError, match="int64"):
        strict_json_loads(b'{"number":9223372036854775808}')
