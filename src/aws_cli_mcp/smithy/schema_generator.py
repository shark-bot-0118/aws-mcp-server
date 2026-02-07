"""JSON Schema generator for Smithy shapes."""

from __future__ import annotations

from aws_cli_mcp.smithy.parser import (
    ListShape,
    MapShape,
    OperationShape,
    SmithyModel,
    StringShape,
    StructureShape,
    UnionShape,
)


class SchemaGenerator:
    def __init__(self, model: SmithyModel) -> None:
        self._model = model

    def generate_operation_input_schema(self, operation_shape_id: str) -> dict[str, object]:
        shape = self._model.get_shape(operation_shape_id)
        if not isinstance(shape, OperationShape):
            raise ValueError(f"Shape is not an operation: {operation_shape_id}")
        if not shape.input:
            schema = {"type": "object", "properties": {}, "additionalProperties": False}
        else:
            schema = self._shape_to_schema(shape.input, {})

        examples: list[object] = []
        if shape.examples:
            for entry in shape.examples:
                if isinstance(entry, dict) and "input" in entry:
                    examples.append(entry["input"])
        example = self._example_for_shape(shape.input) if shape.input else {}
        if example is not None:
            examples.append(example)
        if examples:
            schema["examples"] = examples

        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        return schema

    def _shape_to_schema(
        self, shape_id: str, definitions: dict[str, object], depth: int = 0
    ) -> dict[str, object]:
        if shape_id in definitions:
            return {"$ref": f"#/definitions/{shape_id}"}

        shape = self._model.get_shape(shape_id)
        if shape is None:
            return {"type": "object"}

        # Track recursion to prevent infinite cycles
        if shape_id not in definitions:
            definitions[shape_id] = {}

        if isinstance(shape, StructureShape):
            properties: dict[str, object] = {}
            required: list[str] = []
            for name, member in shape.members.items():
                properties[name] = self._shape_to_schema(member.target, definitions, depth + 1)
                if member.required:
                    required.append(name)
            schema: dict[str, object] = {
                "type": "object",
                "properties": properties,
                "additionalProperties": False,
            }
            if required:
                schema["required"] = required
            if required:
                schema["required"] = required
        elif isinstance(shape, UnionShape):
            # Union types require exactly one member to be set
            properties: dict[str, object] = {}
            for name, member in shape.members.items():
                properties[name] = self._shape_to_schema(member.target, definitions, depth + 1)
            schema: dict[str, object] = {
                "type": "object",
                "properties": properties,
                "additionalProperties": False,
                "minProperties": 1,
                "maxProperties": 1,
            }
        elif isinstance(shape, ListShape):
            schema = {
                "type": "array",
                "items": self._shape_to_schema(shape.member.target, definitions, depth + 1),
            }
        elif shape.type == "document":
             # Document types are free-form JSON
             return {}
        elif isinstance(shape, MapShape):
            schema = {
                "type": "object",
                "additionalProperties": self._shape_to_schema(
                    shape.value.target, definitions, depth + 1
                ),
            }
        elif isinstance(shape, StringShape):
            schema = {"type": "string"}
            if shape.enum:
                schema["enum"] = [entry for entry in shape.enum if entry is not None]
        else:
            schema = self._primitive_schema(shape.type)

        self._apply_traits(schema, getattr(shape, "traits", {}))

        # Update the definition with the full schema
        # If this is the root (depth=0), use a copy in definitions to avoid
        # a circular reference (root -> definitions -> root).
        if depth == 0:
            definitions[shape_id] = schema.copy()
            schema["definitions"] = definitions
        else:
            definitions[shape_id] = schema
            
        return schema

    def _primitive_schema(self, shape_type: str) -> dict[str, object]:
        if shape_type in {"integer", "long", "short", "byte", "bigInteger"}:
            return {"type": "integer"}
        if shape_type in {"float", "double", "bigDecimal"}:
            return {"type": "number"}
        if shape_type == "boolean":
            return {"type": "boolean"}
        if shape_type == "timestamp":
            return {"type": "string", "format": "date-time"}
        if shape_type == "blob":
            return {
                "type": "string",
                "format": "byte",
                "description": "Binary data. Provide as base64-encoded string.",
            }
        return {"type": "string"}

    def _apply_traits(self, schema: dict[str, object], traits: dict[str, object]) -> None:
        pattern = traits.get("smithy.api#pattern")
        if isinstance(pattern, str):
            schema["pattern"] = pattern
        length = traits.get("smithy.api#length")
        if isinstance(length, dict):
            if "min" in length:
                schema["minLength"] = length["min"]
            if "max" in length:
                schema["maxLength"] = length["max"]
        range_trait = traits.get("smithy.api#range")
        if isinstance(range_trait, dict):
            if "min" in range_trait:
                schema["minimum"] = range_trait["min"]
            if "max" in range_trait:
                schema["maximum"] = range_trait["max"]
        if "smithy.api#uniqueItems" in traits:
            schema["uniqueItems"] = True

    def _example_for_shape(self, shape_id: str | None, depth: int = 0) -> object:
        if shape_id is None or depth > 4:
            return None
        shape = self._model.get_shape(shape_id)
        if shape is None:
            return None

        if isinstance(shape, StructureShape):
            example: dict[str, object] = {}
            for name, member in shape.members.items():
                if member.required:
                    example[name] = self._example_for_shape(member.target, depth + 1)
            return example
        if isinstance(shape, UnionShape):
            # Return example for the first member
            for name, member in shape.members.items():
                return {name: self._example_for_shape(member.target, depth + 1)}
            return {}
        if isinstance(shape, ListShape):
            return [self._example_for_shape(shape.member.target, depth + 1)]
        if isinstance(shape, MapShape):
            return {"key": self._example_for_shape(shape.value.target, depth + 1)}
        if isinstance(shape, StringShape):
            if shape.enum:
                return shape.enum[0]
            return "string"
        if shape.type in {"integer", "long", "short", "byte"}:
            return 0
        if shape.type == "boolean":
            return False
        if shape.type == "timestamp":
            return "2024-01-01T00:00:00Z"
        return "string"
