"""Generic bounded catalog serialization and schema compaction, without app imports."""

import json
from collections.abc import Mapping

from .style_rules import check_description

ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}


def compact_schema(value: object) -> object:
    """Remove presentation/default annotations, keeping all validation constraints.

    Properties named title/default are data keys and must never be removed.
    """
    if isinstance(value, dict):
        result = {}
        maps = {"properties", "$defs", "definitions", "patternProperties", "dependentSchemas"}
        arrays = {"allOf", "anyOf", "oneOf", "prefixItems"}
        single = {
            "items",
            "contains",
            "additionalProperties",
            "unevaluatedProperties",
            "propertyNames",
            "not",
            "if",
            "then",
            "else",
        }
        for key, child in value.items():
            if key in {"title", "default"}:
                continue
            if key in maps and isinstance(child, dict):
                result[key] = {name: compact_schema(item) for name, item in child.items()}
            elif key in arrays and isinstance(child, list):
                result[key] = [compact_schema(item) for item in child]
            elif key in single:
                result[key] = compact_schema(child)
            else:
                result[key] = child  # const/enum values are DATA, not schemas.
        return result
    return value


def build_catalog(specs: Mapping[str, tuple[str, dict, dict]]) -> list[dict]:
    if not 1 <= len(specs) <= 32:
        raise ValueError("invalid catalog size")
    result = []
    for name, (description, inputs, outputs) in specs.items():
        if (
            not name
            or len(name) > 64
            or not name.replace("_", "").isalnum()
            or not name.isascii()
            or check_description(description)
        ):
            raise ValueError("invalid tool description or name")
        result.append(
            {
                "name": name,
                "description": description,
                "inputSchema": compact_schema(inputs),
                "outputSchema": compact_schema(outputs),
                "annotations": dict(ANNOTATIONS),
            }
        )
    # This is a serialization bound, not a transport response/frame proof.
    if len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()) > 30 * 1024:
        raise ValueError("catalog requires smaller complete schemas/descriptions")
    return result


def catalog_json(catalog: list[dict]) -> str:
    return json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
