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
    raw_shapes = data.get("shapes")
    if not isinstance(raw_shapes, dict):
        return SmithyModel(shapes=shapes)

    for raw_shape_id, raw_shape_data in raw_shapes.items():
        if not isinstance(raw_shape_id, str) or not isinstance(raw_shape_data, dict):
            continue
        shape_id = raw_shape_id
        shape_data = raw_shape_data

        shape_type_obj = shape_data.get("type")
        if not isinstance(shape_type_obj, str):
            continue
        shape_type = shape_type_obj

        traits_obj = shape_data.get("traits", {}) or {}
        traits = traits_obj if isinstance(traits_obj, dict) else {}

        if shape_type == "structure":
            members: dict[str, Member] = {}
            raw_members = shape_data.get("members") or {}
            if isinstance(raw_members, dict):
                for name, member in raw_members.items():
                    if not isinstance(name, str) or not isinstance(member, dict):
                        continue
                    target = member.get("target")
                    if not isinstance(target, str):
                        continue
                    member_traits = member.get("traits", {}) or {}
                    members[name] = Member(
                        target=target,
                        traits=member_traits if isinstance(member_traits, dict) else {},
                    )
            shapes[shape_id] = StructureShape(
                shape_id=shape_id, type=shape_type, traits=traits, members=members
            )
        elif shape_type == "union":
            union_members: dict[str, Member] = {}
            raw_members = shape_data.get("members") or {}
            if isinstance(raw_members, dict):
                for name, member in raw_members.items():
                    if not isinstance(name, str) or not isinstance(member, dict):
                        continue
                    target = member.get("target")
                    if not isinstance(target, str):
                        continue
                    member_traits = member.get("traits", {}) or {}
                    union_members[name] = Member(
                        target=target,
                        traits=member_traits if isinstance(member_traits, dict) else {},
                    )
            shapes[shape_id] = UnionShape(
                shape_id=shape_id, type=shape_type, traits=traits, members=union_members
            )
        elif shape_type == "list" or shape_type == "set":
            member = shape_data.get("member") or {}
            member_dict = member if isinstance(member, dict) else {}
            target = member_dict.get("target")
            if not isinstance(target, str):
                continue
            member_traits = member_dict.get("traits", {}) or {}
            shapes[shape_id] = ListShape(
                shape_id=shape_id,
                type=shape_type,
                traits=traits,
                member=Member(
                    target=target,
                    traits=member_traits if isinstance(member_traits, dict) else {},
                ),
            )
        elif shape_type == "map":
            key = shape_data.get("key") or {}
            value = shape_data.get("value") or {}
            key_dict = key if isinstance(key, dict) else {}
            value_dict = value if isinstance(value, dict) else {}
            key_target = key_dict.get("target")
            value_target = value_dict.get("target")
            if not isinstance(key_target, str) or not isinstance(value_target, str):
                continue
            key_traits = key_dict.get("traits", {}) or {}
            value_traits = value_dict.get("traits", {}) or {}
            shapes[shape_id] = MapShape(
                shape_id=shape_id,
                type=shape_type,
                traits=traits,
                key=Member(
                    target=key_target,
                    traits=key_traits if isinstance(key_traits, dict) else {},
                ),
                value=Member(
                    target=value_target,
                    traits=value_traits if isinstance(value_traits, dict) else {},
                ),
            )
        elif shape_type == "string":
            enum_values: list[str] | None = None
            enum_trait = traits.get("smithy.api#enum")
            if isinstance(enum_trait, list):
                trait_values: list[str] = []
                for entry in enum_trait:
                    if not isinstance(entry, dict):
                        continue
                    value = entry.get("value")
                    if isinstance(value, str):
                        trait_values.append(value)
                enum_values = trait_values
            raw_shape_enum = shape_data.get("enum")
            if isinstance(raw_shape_enum, list):
                shape_values = [item for item in raw_shape_enum if isinstance(item, str)]
                enum_values = shape_values
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
            input_target = None
            output_target = None
            raw_input = shape_data.get("input") or {}
            raw_output = shape_data.get("output") or {}
            if isinstance(raw_input, dict):
                target = raw_input.get("target")
                if isinstance(target, str):
                    input_target = target
            if isinstance(raw_output, dict):
                target = raw_output.get("target")
                if isinstance(target, str):
                    output_target = target
            shapes[shape_id] = OperationShape(
                shape_id=shape_id,
                type=shape_type,
                traits=traits,
                input=input_target,
                output=output_target,
                documentation=_extract_documentation(shape_data, traits),
                examples=(
                    traits.get("smithy.api#examples")
                    if isinstance(traits.get("smithy.api#examples"), list)
                    else None
                ),
            )
        elif shape_type == "service":
            operations: list[str] = []
            raw_operations = shape_data.get("operations") or []
            if isinstance(raw_operations, list):
                for op in raw_operations:
                    target = op.get("target") if isinstance(op, dict) else op
                    if isinstance(target, str):
                        operations.append(target)
            shapes[shape_id] = ServiceShape(
                shape_id=shape_id,
                type=shape_type,
                traits=traits,
                operations=operations,
            )
        else:
            shapes[shape_id] = Shape(shape_id=shape_id, type=shape_type, traits=traits)

    return SmithyModel(shapes=shapes)


def _extract_documentation(shape_data: dict[str, object], traits: dict[str, object]) -> str | None:
    doc = shape_data.get("documentation")
    if isinstance(doc, str):
        return doc
    doc_trait = traits.get("smithy.api#documentation")
    if isinstance(doc_trait, str):
        return doc_trait
    return None
