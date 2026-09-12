"""guard-json-v1: a deliberately restricted canonical JSON profile."""

import hashlib
import json
import unicodedata

from .errors import GuardError

MAX_BYTES = 131072


def _validate(value, depth=0):
    if depth > 16:
        raise GuardError("json_too_deep", 400)
    if value is None or type(value) is bool:
        return
    if type(value) is int and abs(value) <= 2**53 - 1:
        return
    if type(value) is str:
        if unicodedata.normalize("NFC", value) != value:
            raise GuardError("noncanonical_unicode", 400)
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise GuardError("invalid_unicode", 400) from exc
        return
    if type(value) is list:
        for item in value:
            _validate(item, depth + 1)
        return
    if type(value) is dict and all(type(k) is str for k in value):
        for key, item in value.items():
            _validate(key, depth + 1)
            _validate(item, depth + 1)
        return
    raise GuardError("unsupported_json_value", 400)


def canonical(value, *, max_bytes=MAX_BYTES) -> bytes:
    _validate(value)
    result = json.dumps(value, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(result) > max_bytes:
        raise GuardError("json_too_large", 413)
    return result


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardError("duplicate_json_key", 400)
        result[key] = value
    return result


def loads(raw, *, max_bytes=MAX_BYTES):
    if len(raw) > max_bytes:
        raise GuardError("json_too_large", 413)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
        canonical(value, max_bytes=max_bytes)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise GuardError("invalid_json", 400) from exc


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def fields(value, required):
    if type(value) is not dict or set(value) != set(required):
        raise GuardError("invalid_fields", 400)
