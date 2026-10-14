import pytest

from dev_logs_mcp.shared.mcpkit.style_rules import check_description
from dev_logs_mcp.shared.mcpkit.tools_json import (
    ANNOTATIONS,
    build_catalog,
    catalog_json,
    compact_schema,
)

DESCRIPTION = (
    "Use: test. Inputs: none. Returns: evidence. Bounds: one. Trust: untrusted. Failures: refused."
)


def test_schema_compaction_preserves_data_properties_named_title_and_default():
    schema = {
        "title": "presentation",
        "type": "object",
        "properties": {
            "title": {"title": "nested", "type": "string"},
            "default": {"default": 1, "type": "integer", "minimum": 0},
        },
        "required": ["title"],
        "additionalProperties": False,
    }
    result = compact_schema(schema)
    assert "title" not in result
    assert set(result["properties"]) == {"title", "default"}
    assert result["properties"]["default"] == {"type": "integer", "minimum": 0}
    assert result["required"] == ["title"] and result["additionalProperties"] is False


def test_generic_catalog_is_dependency_explicit_and_readonly():
    catalog = build_catalog({"test": (DESCRIPTION, {"type": "object"}, {"type": "object"})})
    assert catalog[0]["annotations"] == ANNOTATIONS
    assert catalog_json(catalog).endswith("\n")
    assert check_description(DESCRIPTION) == ()


def test_schema_compaction_never_rewrites_const_or_enum_literals():
    schema = {
        "const": {"title": "must-stay", "default": 1},
        "enum": [{"title": "also-stays"}],
        "patternProperties": {"title": {"title": "presentation", "type": "string"}},
    }
    compact = compact_schema(schema)
    assert compact["const"] == schema["const"] and compact["enum"] == schema["enum"]
    assert compact["patternProperties"] == {"title": {"type": "string"}}


@pytest.mark.parametrize(
    "description", ["", "Trust: untrusted. Use: wrong order.", "x" * 1401, DESCRIPTION + "\x00"]
)
def test_description_style_is_machine_checkable(description):
    with pytest.raises(ValueError):
        build_catalog({"test": (description, {}, {})})
