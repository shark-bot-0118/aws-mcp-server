
import sys
import os
import json

# Adjust path to import src
sys.path.append(os.path.join(os.getcwd(), "src"))

from aws_cli_mcp.smithy.schema_generator import SchemaGenerator
from aws_cli_mcp.smithy.parser import SmithyModel, Shape, ListShape, Member

# Manually mock what parser would produce for Document and Set types
# parser.py now produces ListShape for "set" type.

def run_test():
    mock_shapes = {
        "com.test#MyDoc": Shape(shape_id="com.test#MyDoc", type="document", traits={}),
        "com.test#MySet": ListShape(
            shape_id="com.test#MySet", 
            type="set", 
            traits={}, 
            member=Member(target="com.test#MyDoc", traits={})
        ),
    }
    
    model = SmithyModel(shapes=mock_shapes)
    generator = SchemaGenerator(model)
    
    print("Testing JS Types Schema Generation:")
    
    for shape_id in ["com.test#MyDoc", "com.test#MySet"]:
        definitions = {}
        schema = generator._shape_to_schema(shape_id, definitions)
        print(f"\nShape: {shape_id} ({mock_shapes[shape_id].type})")
        print(json.dumps(schema, indent=2))
        
        stype = schema.get("type")
        
        if shape_id == "com.test#MyDoc":
            if stype == "object": # It could return {} which means type is technically implicit any, but schema_generator often adds default type object for unknown?
                 # Actually checking my code, it returns {} for document. which has no "type".
                 # If schema is empty dict, that's valid "Any".
                 pass
            elif stype is None:
                 print("SUCCESS: Document mapped to Any (empty schema)")
            elif stype == "string":
                 print("FAILURE: Document mapped to string")
            else:
                 print(f"SUCCESS?: Mapped to {stype}")

        if shape_id == "com.test#MySet":
            # Set should be array
            if stype == "string":
                 print("FAILURE: Set mapped to string")
            elif stype == "array":
                 print("SUCCESS: Set mapped to array")
            else:
                 print(f"FAILURE: Set mapped to {stype}")

if __name__ == "__main__":
    run_test()
