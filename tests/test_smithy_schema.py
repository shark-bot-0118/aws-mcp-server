from unittest.mock import MagicMock

import pytest

from aws_cli_mcp.smithy.parser import (
    ListShape,
    Member,
    OperationShape,
    SmithyModel,
    StringShape,
    StructureShape,
)
from aws_cli_mcp.smithy.schema_generator import SchemaGenerator


@pytest.fixture
def mock_model():
    model = MagicMock(spec=SmithyModel)
    shapes = {}

    # 1. Input Structure
    input_struct = MagicMock(spec=StructureShape)
    input_struct.members = {
        "SimpleString": Member(target="string-id", traits={"smithy.api#required": {}}),
        "OptionalInt": Member(target="int-id", traits={}),
        "NestedList": Member(target="list-id", traits={"smithy.api#required": {}}),
    }
    input_struct.traits = {}
    shapes["input-id"] = input_struct

    # 2. Primitives
    string_shape = MagicMock(spec=StringShape)
    string_shape.type = "string"
    string_shape.enum = ["A", "B"]
    string_shape.traits = {"smithy.api#length": {"min": 1, "max": 10}}
    shapes["string-id"] = string_shape

    int_shape = MagicMock(spec=OperationShape)  # Reuse generic object? No, usage checks type.
    # We need a generic shape object for primitives that isn't one of the special classes if it falls to 'else'
    # But schema generator uses isinstance checks.
    # For primitives it checks .type attribute on the object if not instance of known classes.
    int_shape = MagicMock()
    int_shape.type = "integer"
    int_shape.traits = {"smithy.api#range": {"min": 0, "max": 100}}
    shapes["int-id"] = int_shape

    # 3. List
    list_shape = MagicMock(spec=ListShape)
    list_shape.member = Member(target="string-id", traits={})
    list_shape.traits = {}
    shapes["list-id"] = list_shape

    # 4. Operation
    op_shape = MagicMock(spec=OperationShape)
    op_shape.input = "input-id"
    op_shape.examples = [{"input": {"SimpleString": "ex"}}]
    shapes["op-id"] = op_shape

    model.get_shape.side_effect = shapes.get
    return model


def test_generate_schema(mock_model):
    gen = SchemaGenerator(mock_model)

    schema = gen.generate_operation_input_schema("op-id")

    assert schema["type"] == "object"
    assert "definitions" in schema

    defs = schema["definitions"]

    # Check Input Structure
    input_def = defs["input-id"]
    assert "required" in input_def
    assert "SimpleString" in input_def["required"]
    assert "OptionalInt" not in input_def["required"]

    # Check String with Enums and Traits
    str_def = defs["string-id"]
    assert str_def["type"] == "string"
    assert str_def["enum"] == ["A", "B"]
    assert str_def["minLength"] == 1
    assert str_def["maxLength"] == 10

    # Check Int with Range
    int_def = defs["int-id"]
    assert int_def["type"] == "integer"
    assert int_def["minimum"] == 0
    assert int_def["maximum"] == 100

    # Check List
    list_def = defs["list-id"]
    assert list_def["type"] == "array"
    assert list_def["items"]["$ref"] == "#/definitions/string-id"  # Recursive ref


def test_generate_schema_no_input(mock_model):
    op = MagicMock(spec=OperationShape)
    op.input = None
    op.examples = []
    mock_model.get_shape.side_effect = None
    mock_model.get_shape.return_value = op

    gen = SchemaGenerator(mock_model)
    schema = gen.generate_operation_input_schema("op-no-input")
    assert schema["type"] == "object"
    assert schema["properties"] == {}


def test_example_generation(mock_model):
    gen = SchemaGenerator(mock_model)
    # Recursion depth is 0
    example = gen._example_for_shape("input-id")
    assert "SimpleString" in example
    assert "NestedList" in example
    assert isinstance(example["NestedList"], list)
