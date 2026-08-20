"""Argument validation (N-07). The rejections are the product."""

from __future__ import annotations

import pytest

from agentboundary.schema import SchemaError, ValidationError, validate

READ_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string", "minLength": 1}},
    "required": ["path"],
}


class TestUnknownKeywordsAreRejected:
    def test_an_unsupported_keyword_raises_rather_than_being_ignored(self) -> None:
        """A silently ignored keyword accepts input the author thought was constrained."""
        with pytest.raises(SchemaError, match="unsupported keyword"):
            validate({"a": 1}, {"type": "object", "oneOf": [{"type": "string"}]})

    def test_the_error_names_the_offending_keyword(self) -> None:
        with pytest.raises(SchemaError) as excinfo:
            validate({}, {"type": "object", "$ref": "#/defs/x"})
        assert "$ref" in str(excinfo.value)

    def test_unsupported_keywords_are_caught_in_nested_schemas_too(self) -> None:
        with pytest.raises(SchemaError, match="unsupported keyword"):
            validate(
                {"inner": {"a": 1}},
                {"type": "object", "properties": {"inner": {"allOf": []}}},
            )


class TestAdditionalPropertiesDefaultsClosed:
    def test_an_unexpected_property_is_refused_by_default(self) -> None:
        """JSON Schema defaults this to true. That default is wrong at a boundary."""
        with pytest.raises(ValidationError, match="unexpected propert"):
            validate({"path": "/a", "callback_url": "http://evil"}, READ_SCHEMA)

    def test_additional_properties_can_be_opened_explicitly(self) -> None:
        schema = {**READ_SCHEMA, "additionalProperties": True}
        assert validate({"path": "/a", "extra": 1}, schema) == {"path": "/a", "extra": 1}

    def test_an_empty_schema_still_refuses_arguments(self) -> None:
        """'No schema' must not come to mean 'anything goes'."""
        with pytest.raises(ValidationError, match="declares no arguments"):
            validate({"path": "/etc/passwd"}, {})

    def test_an_empty_schema_accepts_no_arguments(self) -> None:
        assert validate({}, {}) == {}


class TestRequiredAndTypes:
    def test_a_missing_required_property_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="missing required"):
            validate({}, READ_SCHEMA)

    def test_the_error_names_every_missing_property(self) -> None:
        schema = {
            "type": "object",
            "properties": {},
            "required": ["a", "b"],
            "additionalProperties": True,
        }
        with pytest.raises(ValidationError) as excinfo:
            validate({}, schema)
        assert "a" in str(excinfo.value)
        assert "b" in str(excinfo.value)

    def test_a_wrong_type_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="expected string"):
            validate({"path": 42}, READ_SCHEMA)

    def test_a_boolean_does_not_satisfy_integer(self) -> None:
        """bool subclasses int in Python; a flag must not pass where a count is required."""
        schema = {"type": "object", "properties": {"n": {"type": "integer"}}}
        with pytest.raises(ValidationError, match="got boolean"):
            validate({"n": True}, schema)

    def test_a_boolean_does_not_satisfy_number(self) -> None:
        schema = {"type": "object", "properties": {"n": {"type": "number"}}}
        with pytest.raises(ValidationError, match="got boolean"):
            validate({"n": False}, schema)

    def test_an_integer_satisfies_number(self) -> None:
        schema = {"type": "object", "properties": {"n": {"type": "number"}}}
        assert validate({"n": 3}, schema) == {"n": 3}

    def test_an_unknown_declared_type_is_a_schema_error(self) -> None:
        with pytest.raises(SchemaError, match="unknown type"):
            validate({"a": 1}, {"type": "object", "properties": {"a": {"type": "int"}}})


class TestStringConstraints:
    def test_below_min_length_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="minLength"):
            validate({"path": ""}, READ_SCHEMA)

    def test_above_max_length_is_refused(self) -> None:
        schema = {"type": "object", "properties": {"p": {"type": "string", "maxLength": 3}}}
        with pytest.raises(ValidationError, match="maxLength"):
            validate({"p": "abcd"}, schema)

    def test_a_non_matching_pattern_is_refused(self) -> None:
        schema = {"type": "object", "properties": {"p": {"type": "string", "pattern": "^[a-z]+$"}}}
        with pytest.raises(ValidationError, match="does not match pattern"):
            validate({"p": "AB12"}, schema)

    def test_an_invalid_pattern_is_a_schema_error_not_a_refusal(self) -> None:
        schema = {"type": "object", "properties": {"p": {"type": "string", "pattern": "["}}}
        with pytest.raises(SchemaError, match="invalid pattern"):
            validate({"p": "x"}, schema)

    def test_an_overlong_pattern_is_refused_at_the_schema_level(self) -> None:
        """A schema author cannot be trusted to avoid catastrophic backtracking."""
        schema = {"type": "object", "properties": {"p": {"type": "string", "pattern": "a" * 201}}}
        with pytest.raises(SchemaError, match="pattern exceeds"):
            validate({"p": "x"}, schema)


class TestNumericAndEnumConstraints:
    def test_below_minimum_is_refused(self) -> None:
        schema = {"type": "object", "properties": {"n": {"type": "integer", "minimum": 1}}}
        with pytest.raises(ValidationError, match="below minimum"):
            validate({"n": 0}, schema)

    def test_above_maximum_is_refused(self) -> None:
        schema = {"type": "object", "properties": {"n": {"type": "integer", "maximum": 10}}}
        with pytest.raises(ValidationError, match="above maximum"):
            validate({"n": 11}, schema)

    def test_a_value_outside_the_enum_is_refused(self) -> None:
        schema = {"type": "object", "properties": {"m": {"enum": ["GET", "POST"]}}}
        with pytest.raises(ValidationError, match="permitted enum"):
            validate({"m": "DELETE"}, schema)

    def test_a_const_mismatch_is_refused(self) -> None:
        schema = {"type": "object", "properties": {"v": {"const": 1}}}
        with pytest.raises(ValidationError, match="required const"):
            validate({"v": 2}, schema)


class TestArrays:
    def test_below_min_items_is_refused(self) -> None:
        schema = {"type": "object", "properties": {"xs": {"type": "array", "minItems": 2}}}
        with pytest.raises(ValidationError, match="minItems"):
            validate({"xs": [1]}, schema)

    def test_above_max_items_is_refused(self) -> None:
        schema = {"type": "object", "properties": {"xs": {"type": "array", "maxItems": 1}}}
        with pytest.raises(ValidationError, match="maxItems"):
            validate({"xs": [1, 2]}, schema)

    def test_item_schemas_are_enforced(self) -> None:
        schema = {
            "type": "object",
            "properties": {"xs": {"type": "array", "items": {"type": "string"}}},
        }
        with pytest.raises(ValidationError, match=r"xs\[1\]"):
            validate({"xs": ["a", 2]}, schema)


class TestErrorPaths:
    def test_a_nested_failure_names_its_path(self) -> None:
        """An operator has to find the offending field without guessing."""
        schema = {
            "type": "object",
            "properties": {"outer": {"type": "object", "properties": {"n": {"type": "integer"}}}},
        }
        with pytest.raises(ValidationError, match=r"outer\.n"):
            validate({"outer": {"n": "x"}}, schema)


class TestValidatedFormIsReturned:
    def test_the_validated_arguments_are_returned_for_downstream_use(self) -> None:
        """FR-008: every downstream check consumes this, never the raw proposal."""
        assert validate({"path": "/srv/a"}, READ_SCHEMA) == {"path": "/srv/a"}

    def test_the_returned_mapping_is_a_copy(self) -> None:
        """Mutating the caller's proposal must not reach the validated form."""
        proposal = {"path": "/srv/a"}
        validated = validate(proposal, READ_SCHEMA)
        proposal["path"] = "/etc/passwd"
        assert validated["path"] == "/srv/a"

    def test_a_non_mapping_schema_is_a_schema_error(self) -> None:
        with pytest.raises(SchemaError, match="must be a mapping"):
            validate({}, ["not", "a", "schema"])  # type: ignore[arg-type]
