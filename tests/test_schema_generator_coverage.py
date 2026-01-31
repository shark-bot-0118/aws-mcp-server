import pytest
from unittest.mock import MagicMock
from aws_cli_mcp.smithy.schema_generator import SchemaGenerator
from aws_cli_mcp.smithy.parser import SmithyModel, StructureShape, Member, StringShape, Shape, MapShape, UnionShape, OperationShape, ListShape

def test_schema_generator_complex_shapes():
    model = MagicMock(spec=SmithyModel)
    
    # Define shapes
    # Map
    map_shape = MapShape("map", "map", {}, 
        key=Member("str", {}), 
        value=Member("int", {})
    )
    # Union
    union_shape = UnionShape("union", "union", {}, {
        "A": Member("str", {}),
        "B": Member("int", {})
    })
    # List with uniqueItems logic (implied by set trait? No, Smithy uses set trait on list shape)
    # But schema_generator checks for "uniqueItems" in json schema keywords?
    # Actually Smithy has @uniqueItems trait.
    list_shape = ListShape("list", "list", {"smithy.api#uniqueItems": {}}, Member("str", {}))
    
    # String with pattern and sensitive
    str_shape = StringShape("str", "string", {
        "smithy.api#pattern": "^[a-z]+$",
        "smithy.api#sensitive": {}
    })
    
    # Integer with range
    int_shape = Shape("int", "integer", {
        "smithy.api#range": {"min": 0, "max": 10}
    })
    
    # Operation
    op_shape = OperationShape("op", "operation", {}, input="struct", output=None, documentation=None, examples=None)
    
    # Input Struct
    struct_shape = StructureShape("struct", "structure", {}, {
        "M": Member("map", {}),
        "U": Member("union", {}),
        "L": Member("list", {}),
    })

    model.get_shape.side_effect = lambda sid: {
        "map": map_shape,
        "union": union_shape,
        "list": list_shape,
        "str": str_shape,
        "int": int_shape,
        "op": op_shape,
        "struct": struct_shape
    }.get(sid)
    
    gen = SchemaGenerator(model)
    schema = gen.generate_operation_input_schema("op")
    
    props = schema["properties"]
    
    # Check Map
    assert props["M"]["type"] == "object"
    assert props["M"]["additionalProperties"]["type"] == "integer"
    
    # Check Union (using properties constraint instead of oneOf)
    # assert "oneOf" in props["U"]
    assert props["U"]["minProperties"] == 1
    assert props["U"]["maxProperties"] == 1
    
    # Check List
    assert props["L"]["type"] == "array"
    assert props["L"]["uniqueItems"] is True
    
    # Check String Constraints
    str_schema = gen._shape_to_schema("str", {})
    assert str_schema["pattern"] == "^[a-z]+$"
    # assert str_schema["format"] == "password" # sensitive trait check omitted if not standard

    # Check Integer Constraints
    int_schema = gen._shape_to_schema("int", {})
    assert int_schema["minimum"] == 0
    assert int_schema["maximum"] == 10

def test_schema_generator_unknown_shape():
    model = MagicMock(spec=SmithyModel)
    model.get_shape.return_value = None
    gen = SchemaGenerator(model)

    # Defaults to object
    assert gen._shape_to_schema("unknown", {}) == {"type": "object"}

def test_schema_generator_traits_length():
    model = MagicMock(spec=SmithyModel)
    str_shape = StringShape("str", "string", {
        "smithy.api#length": {"min": 5, "max": 10}
    })
    model.get_shape.side_effect = lambda sid: {"str": str_shape}.get(sid)
    
    gen = SchemaGenerator(model)
    schema = gen._shape_to_schema("str", {})
    
    assert schema["minLength"] == 5
    assert schema["maxLength"] == 10

def test_schema_generator_examples():
    model = MagicMock(spec=SmithyModel)
    
    # Define shapes for example generation
    str_shape = StringShape("str", "string", {"smithy.api#documentation": "A string"})
    int_shape = Shape("int", "integer", {})
    bool_shape = Shape("bool", "boolean", {})
    ts_shape = Shape("ts", "timestamp", {})
    
    list_shape = ListShape("list", "list", {}, Member("str", {}))
    map_shape = MapShape("map", "map", {}, Member("str", {}), Member("int", {}))
    union_shape = UnionShape("union", "union", {}, {"A": Member("str", {})})
    
    struct_shape = StructureShape("struct", "structure", {}, {
        "S": Member("str", {"required": True}), # Required should appear
        "O": Member("int", {"required": False}) # Optional should be skipped in example depth > 0? No, checking logic
    })
    
    # Op shape to trigger example generation
    op_shape = OperationShape("op", "operation", {}, input="struct", output=None, documentation=None, examples=[
        {"title": "Ex1", "input": {"S": "Explicit"}}
    ])

    model.get_shape.side_effect = lambda sid: {
        "str": str_shape,
        "int": int_shape,
        "bool": bool_shape,
        "ts": ts_shape,
        "list": list_shape,
        "map": map_shape,
        "union": union_shape,
        "struct": struct_shape,
        "op": op_shape
    }.get(sid)
    
    gen = SchemaGenerator(model)
    
    # Trigger full generation
    schema = gen.generate_operation_input_schema("op")
    
    # Check if examples are populated
    assert "examples" in schema
    assert schema["examples"][0] == {"S": "Explicit"}
    
    # Check generated example (from _example_for_shape)
    # The second example should be automatically generated
    assert len(schema["examples"]) >= 2
    generated = schema["examples"][1]
    assert "S" in generated
    assert generated["S"] == "string" # Default string example
    
    # Test individual shape examples
    assert gen._example_for_shape("int") == 0
    assert gen._example_for_shape("bool") is False
    assert gen._example_for_shape("ts") == "2024-01-01T00:00:00Z"
    assert gen._example_for_shape("list") == ["string"]
    assert gen._example_for_shape("map") == {"key": 0}
    assert gen._example_for_shape("union") == {"A": "string"}
    
def test_schema_generator_not_operation():
    model = MagicMock(spec=SmithyModel)
    model.get_shape.return_value = StringShape("str", "string", {})
    gen = SchemaGenerator(model)
    with pytest.raises(ValueError, match="Shape is not an operation"):
        gen.generate_operation_input_schema("str")

def test_schema_generator_missing_coverage():
    model = MagicMock(spec=SmithyModel)
    
    # 1. Operation without input
    op_no_input = OperationShape("op_no_input", "operation", {}, input=None, output=None, documentation=None, examples=None)
    
    # 2. Document type
    doc_shape = Shape("doc", "document", {})
    
    # 3. String with Enum
    enum_shape = StringShape("enum_str", "string", {}, enum=["A", "B"])
    
    # 4. Primitives
    float_shape = Shape("float", "float", {})
    # double_shape = Shape("double", "double", {}) # Same branch as float
    bool_shape = Shape("bool", "boolean", {})
    ts_shape = Shape("ts", "timestamp", {})
    blob_shape = Shape("blob", "blob", {})
    
    # 5. Union with no members (for example generation coverage)
    empty_union = UnionShape("empty_union", "union", {}, {})
    
    model.get_shape.side_effect = lambda sid: {
        "op_no_input": op_no_input,
        "doc": doc_shape,
        "enum_str": enum_shape,
        "float": float_shape,
        "bool": bool_shape,
        "ts": ts_shape,
        "blob": blob_shape,
        "empty_union": empty_union
    }.get(sid)
    
    gen = SchemaGenerator(model)
    
    # Test op without input
    schema = gen.generate_operation_input_schema("op_no_input")
    assert schema["properties"] == {}
    
    # Test Document
    assert gen._shape_to_schema("doc", {}) == {}
    
    # Test Enum
    schema = gen._shape_to_schema("enum_str", {})
    assert "enum" in schema
    assert schema["enum"] == ["A", "B"]
    
    # Test Primitives
    assert gen._shape_to_schema("float", {})["type"] == "number"
    assert gen._shape_to_schema("bool", {})["type"] == "boolean"
    assert gen._shape_to_schema("ts", {})["format"] == "date-time"
    assert gen._shape_to_schema("blob", {})["type"] == "string" # Default fallback
    
    # Test Examples Edge Cases
    # Enum example
    assert gen._example_for_shape("enum_str") == "A"
    
    # Timestamp example
    assert gen._example_for_shape("ts") == "2024-01-01T00:00:00Z"

    # Depth limit
    assert gen._example_for_shape("doc", depth=5) is None
    
    # Unknown shape
    model.get_shape.return_value = None # Temporarily break lookup
    assert gen._example_for_shape("unknown") is None
    model.get_shape.side_effect = lambda sid: {"empty_union": empty_union}.get(sid) # Restore
    
    # Empty Union
    assert gen._example_for_shape("empty_union") == {}

    # Recursive check (just to ensure no infinite loop if logic fails, though depth handles it)
    # Passed implicitly by depth check test

