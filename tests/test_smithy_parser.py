from aws_cli_mcp.smithy.parser import (
    ListShape,
    MapShape,
    OperationShape,
    ServiceShape,
    StringShape,
    StructureShape,
    UnionShape,
    parse_model,
)


def test_parse_model_all_shapes():
    data = {
        "shapes": {
            "ns#Struct": {
                "type": "structure",
                "members": {"Field": {"target": "ns#String", "traits": {"required": {}}}},
            },
            "ns#List": {"type": "list", "member": {"target": "ns#String"}},
            "ns#Map": {
                "type": "map",
                "key": {"target": "ns#String"},
                "value": {"target": "ns#Struct"},
            },
            "ns#String": {"type": "string", "traits": {"smithy.api#length": {"min": 1}}},
            "ns#EnumString": {
                "type": "string",
                "traits": {"smithy.api#enum": [{"value": "A"}, {"value": "B"}]},
            },
            "ns#EnumString2": {
                "type": "string",
                "enum": ["X", "Y"],
            },
            "ns#Union": {
                "type": "union",
                "members": {"OptionA": {"target": "ns#String"}, "OptionB": {"target": "ns#Struct"}},
            },
            "ns#Operation": {
                "type": "operation",
                "input": {"target": "ns#Struct"},
                "output": {"target": "ns#Struct"},
                "errors": [{"target": "ns#Error"}],
                "documentation": "Docs",
                "traits": {"smithy.api#examples": [{"input": {}}]},
            },
            "ns#Service": {"type": "service", "operations": [{"target": "ns#Operation"}]},
            "ns#OperationTraitDoc": {
                "type": "operation",
                "input": {"target": "ns#Struct"},
                "traits": {"smithy.api#documentation": "Trait docs"},
            },
            "ns#Integer": {"type": "integer"},
            "ns#Blob": {"type": "blob"},
            "ns#Timestamp": {"type": "timestamp"},
            "ns#Document": {"type": "document"},
            "ns#CustomShape": {"type": "customType"},
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
    es2 = model.get_shape("ns#EnumString2")
    assert isinstance(es2, StringShape)
    assert es2.enum == ["X", "Y"]

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
    op_trait_doc = model.get_shape("ns#OperationTraitDoc")
    assert isinstance(op_trait_doc, OperationShape)
    assert op_trait_doc.documentation == "Trait docs"

    # Verify Service
    svc = model.get_shape("ns#Service")
    assert isinstance(svc, ServiceShape)
    assert "ns#Operation" in svc.operations

    # Verify Primitives
    assert model.get_shape("ns#Integer").type == "integer"
    assert model.get_shape("ns#Blob").type == "blob"
    assert model.get_shape("ns#CustomShape").type == "customType"


def test_extract_documentation_returns_none_for_non_string_trait() -> None:
    data = {
        "shapes": {
            "ns#OperationTraitDocBad": {
                "type": "operation",
                "input": {"target": "ns#Struct"},
                "traits": {"smithy.api#documentation": {"text": "not-string"}},
            },
            "ns#Struct": {"type": "structure", "members": {}},
        }
    }
    model = parse_model(data)
    op = model.get_shape("ns#OperationTraitDocBad")
    assert isinstance(op, OperationShape)
    assert op.documentation is None


def test_parse_model_skips_invalid_members_and_shapes() -> None:
    assert parse_model({"shapes": []}).shapes == {}

    data = {
        "shapes": {
            1: {"type": "structure"},
            "ns#NotDict": "bad",
            "ns#MissingType": {"type": 123},
            "ns#Struct": {
                "type": "structure",
                "members": {
                    "BadMemberType": "x",
                    "NoTarget": {"traits": {"required": {}}},
                    1: {"target": "ns#String"},
                },
            },
            "ns#Union": {
                "type": "union",
                "members": {
                    "BadMemberType": "x",
                    "NoTarget": {},
                },
            },
            "ns#ListMissingTarget": {"type": "list", "member": {}},
            "ns#MapMissingTargets": {"type": "map", "key": {}, "value": {}},
            "ns#StringEnumTraitBad": {
                "type": "string",
                "traits": {"smithy.api#enum": [123, {"value": "A"}]},
            },
        }
    }

    model = parse_model(data)
    assert model.get_shape("ns#Struct") is not None
    assert model.get_shape("ns#Union") is not None
    assert model.get_shape("ns#ListMissingTarget") is None
    assert model.get_shape("ns#MapMissingTargets") is None
    enum_shape = model.get_shape("ns#StringEnumTraitBad")
    assert isinstance(enum_shape, StringShape)
    assert enum_shape.enum == ["A"]
