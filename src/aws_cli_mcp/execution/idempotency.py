"""Idempotency token injection based on Smithy traits."""

from __future__ import annotations

from uuid import uuid4

from aws_cli_mcp.smithy.parser import OperationShape, SmithyModel, StructureShape


def inject_idempotency_tokens(
    model: SmithyModel, operation_shape_id: str, params: dict[str, object]
) -> tuple[dict[str, object], list[str]]:
    shape = model.get_shape(operation_shape_id)
    if not isinstance(shape, OperationShape) or not shape.input:
        return params, []

    input_shape = model.get_shape(shape.input)
    if not isinstance(input_shape, StructureShape):
        return params, []

    updated = dict(params)
    injected: list[str] = []
    for member_name, member in input_shape.members.items():
        if "smithy.api#idempotencyToken" in member.traits:
            if member_name not in updated:
                token = uuid4().hex
                updated[member_name] = token
                injected.append(member_name)

    return updated, injected
