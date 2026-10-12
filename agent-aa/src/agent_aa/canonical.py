"""ZTCANON-JSON-v1 deterministic JSON encoding.

The profile intentionally accepts fewer values than generic JSON: signed data may
contain strings, booleans, null, signed 64-bit integers, arrays, and objects with
string keys. Floats and duplicate object keys are rejected.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel

from .errors import CanonicalizationError

MIN_INT64 = -(2**63)
MAX_INT64 = 2**63 - 1


def _validate_string(value: str, *, label: str) -> None:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(f"{label} is not valid Unicode") from exc


def _normalize(value: Any, *, path: str = "$") -> Any:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python", exclude_none=False)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not MIN_INT64 <= value <= MAX_INT64:
            raise CanonicalizationError(f"integer at {path} is outside int64")
        return value
    if isinstance(value, float):
        raise CanonicalizationError(f"floating-point value at {path} is forbidden")
    if isinstance(value, str):
        _validate_string(value, label=path)
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"object key at {path} is not a string")
            _validate_string(key, label=f"key at {path}")
            result[key] = _normalize(item, path=f"{path}.{key}")
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    raise CanonicalizationError(f"unsupported value at {path}: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return the unique UTF-8 byte representation for a protocol object."""

    normalized = _normalize(value)
    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(str(exc)) from exc
    return encoded.encode("utf-8", errors="strict")


def _reject_float(_: str) -> None:
    raise CanonicalizationError("floating-point JSON numbers are forbidden")


def _parse_int(value: str) -> int:
    parsed = int(value)
    if not MIN_INT64 <= parsed <= MAX_INT64:
        raise CanonicalizationError("JSON integer is outside int64")
    return parsed


def _reject_constant(value: str) -> None:
    raise CanonicalizationError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def strict_json_loads(data: bytes | str) -> Any:
    """Parse JSON while rejecting duplicate keys, floats, and non-finite values."""

    try:
        value = json.loads(
            data,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise CanonicalizationError("input is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise CanonicalizationError(f"invalid JSON: {exc.msg}") from exc
    return _normalize(value)
