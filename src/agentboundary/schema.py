"""Argument schema validation -- FR-006 to FR-008.

A deliberately small subset of JSON Schema, implemented here rather than
pulled in. Validation sits **on** the authorisation path, and every dependency
on that path is code an attacker's payload eventually reaches (ADR-0005). A
full validator brings a transitive tree and a much larger behaviour surface in
exchange for keywords this project does not use.

Supported: ``type`` (object, string, integer, number, boolean, array, null),
``properties``, ``required``, ``additionalProperties``, ``enum``, ``const``,
``minLength``, ``maxLength``, ``pattern``, ``minimum``, ``maximum``,
``minItems``, ``maxItems``, ``items``.

Two rules govern the whole module:

* **Unknown keywords are an error, not a no-op.** A validator that ignores a
  keyword it does not implement will happily accept input the schema author
  believed was constrained. Failing loudly at registration is the only safe
  reading.
* **``additionalProperties`` defaults to false.** JSON Schema defaults it to
  true; that default is wrong for an authorisation boundary, where an
  unexpected field is exactly the thing you want refused.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

__all__ = ["SchemaError", "ValidationError", "validate"]

_SUPPORTED_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "enum",
        "const",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
        "minItems",
        "maxItems",
        "items",
        "description",
        "title",
    }
)

_TYPE_MAP: Final[dict[str, tuple[type, ...]]] = {
    "object": (dict,),
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list, tuple),
    "null": (type(None),),
}

#: Cap on pattern length. A schema author cannot be trusted to avoid a
#: catastrophically backtracking regex, and a schema is configuration -- which
#: this project treats as security-relevant but not as trusted code.
_MAX_PATTERN_LENGTH: Final[int] = 200


class SchemaError(Exception):
    """The schema itself is malformed. A registration-time defect, not input."""


class ValidationError(Exception):
    """The arguments do not satisfy the schema. Becomes ``schema_invalid``."""


def _check_keywords(schema: Mapping[str, Any], path: str) -> None:
    unknown = sorted(set(schema) - _SUPPORTED_KEYWORDS)
    if unknown:
        msg = (
            f"schema at {path or '<root>'} uses unsupported keyword(s): "
            f"{', '.join(unknown)}. Unsupported keywords are rejected rather "
            f"than ignored -- ignoring one would silently accept input the "
            f"schema author believed was constrained."
        )
        raise SchemaError(msg)


def _check_type(value: Any, expected: str, path: str) -> None:
    permitted = _TYPE_MAP.get(expected)
    if permitted is None:
        msg = f"schema at {path or '<root>'}: unknown type {expected!r}"
        raise SchemaError(msg)
    # bool is a subclass of int in Python; a boolean must not satisfy
    # "integer" or "number", or a flag would pass where a count was required.
    if expected in {"integer", "number"} and isinstance(value, bool):
        msg = f"{path or 'value'}: expected {expected}, got boolean"
        raise ValidationError(msg)
    if not isinstance(value, permitted):
        got = type(value).__name__
        msg = f"{path or 'value'}: expected {expected}, got {got}"
        raise ValidationError(msg)


def _check_string(value: str, schema: Mapping[str, Any], path: str) -> None:
    min_length = schema.get("minLength")
    if isinstance(min_length, int) and len(value) < min_length:
        msg = f"{path or 'value'}: shorter than minLength {min_length}"
        raise ValidationError(msg)
    max_length = schema.get("maxLength")
    if isinstance(max_length, int) and len(value) > max_length:
        msg = f"{path or 'value'}: longer than maxLength {max_length}"
        raise ValidationError(msg)
    pattern = schema.get("pattern")
    if isinstance(pattern, str):
        if len(pattern) > _MAX_PATTERN_LENGTH:
            msg = f"schema at {path or '<root>'}: pattern exceeds {_MAX_PATTERN_LENGTH} characters"
            raise SchemaError(msg)
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            msg = f"schema at {path or '<root>'}: invalid pattern -- {exc}"
            raise SchemaError(msg) from exc
        if compiled.search(value) is None:
            msg = f"{path or 'value'}: does not match pattern"
            raise ValidationError(msg)


def _check_number(value: float, schema: Mapping[str, Any], path: str) -> None:
    minimum = schema.get("minimum")
    if isinstance(minimum, (int, float)) and value < minimum:
        msg = f"{path or 'value'}: below minimum {minimum}"
        raise ValidationError(msg)
    maximum = schema.get("maximum")
    if isinstance(maximum, (int, float)) and value > maximum:
        msg = f"{path or 'value'}: above maximum {maximum}"
        raise ValidationError(msg)


def _check_array(value: Sequence[Any], schema: Mapping[str, Any], path: str) -> list[Any]:
    min_items = schema.get("minItems")
    if isinstance(min_items, int) and len(value) < min_items:
        msg = f"{path or 'value'}: fewer than minItems {min_items}"
        raise ValidationError(msg)
    max_items = schema.get("maxItems")
    if isinstance(max_items, int) and len(value) > max_items:
        msg = f"{path or 'value'}: more than maxItems {max_items}"
        raise ValidationError(msg)
    item_schema = schema.get("items")
    if not isinstance(item_schema, Mapping):
        return list(value)
    return [_validate(item, item_schema, f"{path}[{index}]") for index, item in enumerate(value)]


def _check_object(value: Mapping[str, Any], schema: Mapping[str, Any], path: str) -> dict[str, Any]:
    properties = schema.get("properties")
    properties = properties if isinstance(properties, Mapping) else {}

    required = schema.get("required")
    if isinstance(required, Sequence) and not isinstance(required, str):
        missing = sorted(name for name in required if name not in value)
        if missing:
            msg = f"{path or 'value'}: missing required propert(ies): {', '.join(missing)}"
            raise ValidationError(msg)

    # Default false, unlike JSON Schema. At an authorisation boundary an
    # unexpected field is precisely what should be refused.
    if not schema.get("additionalProperties", False):
        extra = sorted(set(value) - set(properties))
        if extra:
            msg = (
                f"{path or 'value'}: unexpected propert(ies): {', '.join(extra)}. "
                f"additionalProperties defaults to false at an authorisation boundary."
            )
            raise ValidationError(msg)

    validated: dict[str, Any] = {}
    for name, item in value.items():
        sub_schema = properties.get(name)
        child_path = f"{path}.{name}" if path else name
        validated[name] = (
            _validate(item, sub_schema, child_path) if isinstance(sub_schema, Mapping) else item
        )
    return validated


def _validate(value: Any, schema: Mapping[str, Any], path: str) -> Any:
    _check_keywords(schema, path)

    if "const" in schema and value != schema["const"]:
        msg = f"{path or 'value'}: does not equal the required const"
        raise ValidationError(msg)

    enum = schema.get("enum")
    if isinstance(enum, Sequence) and not isinstance(enum, str) and value not in enum:
        msg = f"{path or 'value'}: not one of the permitted enum values"
        raise ValidationError(msg)

    declared = schema.get("type")
    if isinstance(declared, str):
        _check_type(value, declared, path)

    if isinstance(value, str):
        _check_string(value, schema, path)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        _check_number(value, schema, path)
    elif isinstance(value, (list, tuple)):
        return _check_array(value, schema, path)
    elif isinstance(value, Mapping):
        return _check_object(value, schema, path)

    return value


def validate(arguments: Mapping[str, Any], schema: Mapping[str, Any]) -> dict[str, Any]:
    """Validate proposed arguments and return the validated form.

    The **return value** is what every downstream check, the attribution, and
    the audit record must consume (FR-008). Callers that keep using the raw
    proposal after calling this have reintroduced the gap this function exists
    to close: a confinement check on an unvalidated path argument is a check on
    a value the broker never agreed to.

    Raises:
        SchemaError: the schema is malformed -- a registration-time defect.
        ValidationError: the arguments do not satisfy it -- becomes a refusal.
    """
    # Checked at runtime despite the annotation: tool schemas are loaded from
    # configuration, and configuration is security-relevant here but not
    # type-checked. Widening to `object` first stops the type checker from
    # narrowing away a guard that a real caller can still trip.
    declared: object = schema
    if not isinstance(declared, Mapping):
        msg = "schema must be a mapping"
        raise SchemaError(msg)
    # An empty schema constrains nothing. That is a legitimate choice for a
    # no-argument tool, so it is permitted -- but it must still reject
    # arguments, or "no schema" would mean "anything goes".
    if not schema:
        if arguments:
            msg = "value: tool declares no arguments, but arguments were supplied"
            raise ValidationError(msg)
        return {}
    # A mapping always routes through _check_object, which returns a dict.
    validated: dict[str, Any] = _validate(dict(arguments), schema, "")
    return validated
