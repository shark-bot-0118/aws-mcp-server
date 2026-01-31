"""Smithy model parser for AWS API definitions (JSON format)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Member:
    target: str
    traits: dict[str, object]

    @property
    def required(self) -> bool:
        return "smithy.api#required" in self.traits or "required" in self.traits


@dataclass
class Shape:
    shape_id: str
    type: str
    traits: dict[str, object]


@dataclass
class StructureShape(Shape):
    members: dict[str, Member]


@dataclass
class ListShape(Shape):
    member: Member


@dataclass
class MapShape(Shape):
    key: Member
    value: Member


@dataclass
class UnionShape(Shape):
    members: dict[str, Member]


@dataclass
class StringShape(Shape):
    enum: list[str] | None = None


@dataclass
class OperationShape(Shape):
    input: str | None
    output: str | None
    documentation: str | None
    examples: list[dict[str, object]] | None


@dataclass
class ServiceShape(Shape):
    operations: list[str]


@dataclass
class SmithyModel:
    shapes: dict[str, Shape]

    def get_shape(self, shape_id: str) -> Shape | None:
        return self.shapes.get(shape_id)


def parse_model(data: dict[str, object]) -> SmithyModel:
    shapes: dict[str, Shape] = {}
    for shape_id, shape_data in data.get("shapes", {}).items():
        shape_type = shape_data.get("type")
        traits = shape_data.get("traits", {}) or {}
        if shape_type == "structure":
            members: dict[str, Member] = {}
            for name, member in (shape_data.get("members") or {}).items():
                members[name] = Member(target=member["target"], traits=member.get("traits", {}) or {})
            shapes[shape_id] = StructureShape(
                shape_id=shape_id, type=shape_type, traits=traits, members=members
            )
        elif shape_type == "union":
            members: dict[str, Member] = {}
            for name, member in (shape_data.get("members") or {}).items():
                members[name] = Member(target=member["target"], traits=member.get("traits", {}) or {})
            shapes[shape_id] = UnionShape(
                shape_id=shape_id, type=shape_type, traits=traits, members=members
            )
        elif shape_type == "list" or shape_type == "set":
            member = shape_data.get("member") or {}
            shapes[shape_id] = ListShape(
                shape_id=shape_id,
                type=shape_type,
                traits=traits,
                member=Member(target=member["target"], traits=member.get("traits", {}) or {}),
            )
        elif shape_type == "map":
            key = shape_data.get("key") or {}
            value = shape_data.get("value") or {}
            shapes[shape_id] = MapShape(
                shape_id=shape_id,
                type=shape_type,
                traits=traits,
                key=Member(target=key["target"], traits=key.get("traits", {}) or {}),
                value=Member(target=value["target"], traits=value.get("traits", {}) or {}),
            )
        elif shape_type == "string":
            enum_values = None
            enum_trait = traits.get("smithy.api#enum")
            if isinstance(enum_trait, list):
                enum_values = [entry.get("value") for entry in enum_trait if "value" in entry]
            if isinstance(shape_data.get("enum"), list):
                enum_values = shape_data.get("enum")
            shapes[shape_id] = StringShape(
                shape_id=shape_id,
                type=shape_type,
                traits=traits,
                enum=enum_values,
            )
        elif shape_type in {
            "integer",
            "long",
            "short",
            "byte",
            "boolean",
            "timestamp",
            "float",
            "double",
            "bigInteger",
            "bigDecimal",
            "blob",
            "document",
        }:
            shapes[shape_id] = Shape(shape_id=shape_id, type=shape_type, traits=traits)
        elif shape_type == "operation":
            shapes[shape_id] = OperationShape(
                shape_id=shape_id,
                type=shape_type,
                traits=traits,
                input=(shape_data.get("input") or {}).get("target"),
                output=(shape_data.get("output") or {}).get("target"),
                documentation=_extract_documentation(shape_data, traits),
                examples=traits.get("smithy.api#examples"),
            )
        elif shape_type == "service":
            shapes[shape_id] = ServiceShape(
                shape_id=shape_id,
                type=shape_type,
                traits=traits,
                operations=[
                    (op.get("target") if isinstance(op, dict) else op)
                    for op in (shape_data.get("operations") or [])
                ],
            )
        else:
            shapes[shape_id] = Shape(shape_id=shape_id, type=shape_type, traits=traits)

    return SmithyModel(shapes=shapes)


def _extract_documentation(shape_data: dict[str, object], traits: dict[str, object]) -> str | None:
    if "documentation" in shape_data:
        return shape_data["documentation"]
    doc_trait = traits.get("smithy.api#documentation")
    if isinstance(doc_trait, str):
        return doc_trait
    return None
