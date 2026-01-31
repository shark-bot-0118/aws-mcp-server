
from aws_cli_mcp.smithy.parser import parse_model, StructureShape, ListShape, MapShape, StringShape, OperationShape, ServiceShape, UnionShape

def test_parse_model_all_shapes():
    data = {
        "shapes": {
            "ns#Struct": {
                "type": "structure",
                "members": {
                    "Field": {"target": "ns#String", "traits": {"required": {}}}
                }
            },
            "ns#List": {
                "type": "list",
                "member": {"target": "ns#String"}
            },
            "ns#Map": {
                "type": "map",
                "key": {"target": "ns#String"},
                "value": {"target": "ns#Struct"}
            },
            "ns#String": {
                "type": "string",
                "traits": {"smithy.api#length": {"min": 1}}
            },
            "ns#EnumString": {
                "type": "string",
                "traits": {
                    "smithy.api#enum": [{"value": "A"}, {"value": "B"}]
                }
            },
            "ns#Union": {
                "type": "union",
                "members": {
                    "OptionA": {"target": "ns#String"},
                    "OptionB": {"target": "ns#Struct"}
                }
            },
            "ns#Operation": {
                "type": "operation",
                "input": {"target": "ns#Struct"},
                "output": {"target": "ns#Struct"},
                "errors": [{"target": "ns#Error"}],
                "documentation": "Docs",
                "traits": {
                    "smithy.api#examples": [{"input": {}}]
                }
            },
            "ns#Service": {
                "type": "service",
                "operations": [{"target": "ns#Operation"}]
            },
            "ns#Integer": {"type": "integer"},
            "ns#Blob": {"type": "blob"},
            "ns#Timestamp": {"type": "timestamp"},
            "ns#Document": {"type": "document"}
        }
    }

    model = parse_model(data)
    
    # Verify Structure
    struct = model.get_shape("ns#Struct")
    assert isinstance(struct, StructureShape)
    assert "Field" in struct.members
    assert struct.members["Field"].target == "ns#String"
    assert struct.members["Field"].required

    # Verify List
    lst = model.get_shape("ns#List")
    assert isinstance(lst, ListShape)
    assert lst.member.target == "ns#String"

    # Verify Map
    mp = model.get_shape("ns#Map")
    assert isinstance(mp, MapShape)
    assert mp.key.target == "ns#String"
    assert mp.value.target == "ns#Struct"
    
    # Verify String & Enum
    s = model.get_shape("ns#String")
    assert isinstance(s, StringShape)
    assert s.traits["smithy.api#length"]["min"] == 1
    
    es = model.get_shape("ns#EnumString")
    assert isinstance(es, StringShape)
    assert "A" in es.enum
    
    # Verify Union
    u = model.get_shape("ns#Union")
    assert isinstance(u, UnionShape)
    assert "OptionA" in u.members

    # Verify Operation
    op = model.get_shape("ns#Operation")
    assert isinstance(op, OperationShape)
    assert op.input == "ns#Struct"
    assert op.documentation == "Docs"
    assert len(op.examples) == 1
    
    # Verify Service
    svc = model.get_shape("ns#Service")
    assert isinstance(svc, ServiceShape)
    assert "ns#Operation" in svc.operations

    # Verify Primitives
    assert model.get_shape("ns#Integer").type == "integer"
    assert model.get_shape("ns#Blob").type == "blob"
