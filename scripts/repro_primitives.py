
import sys
import os
import json
from unittest.mock import MagicMock

# Adjust path to import src
sys.path.append(os.path.join(os.getcwd(), "src"))

from aws_cli_mcp.smithy.schema_generator import SchemaGenerator
from aws_cli_mcp.smithy.parser import SmithyModel, Shape, StringShape

def run_test():
    # Manually construct a SmithyModel with various primitive shapes
    # to see how SchemaGenerator handles them.
    
    mock_shapes = {
        "com.test#Float": Shape(shape_id="com.test#Float", type="float", traits={}),
        "com.test#Double": Shape(shape_id="com.test#Double", type="double", traits={}),
        "com.test#Blob": Shape(shape_id="com.test#Blob", type="blob", traits={}),
        "com.test#BigInteger": Shape(shape_id="com.test#BigInteger", type="bigInteger", traits={}),
        "com.test#BigDecimal": Shape(shape_id="com.test#BigDecimal", type="bigDecimal", traits={}),
    }
    
    model = SmithyModel(shapes=mock_shapes)
    generator = SchemaGenerator(model)
    
    print("Testing Primitives Schema Generation:")
    
    primitives = ["com.test#Float", "com.test#Double", "com.test#Blob", "com.test#BigInteger", "com.test#BigDecimal"]
    
    for shape_id in primitives:
        # We need to expose a way to generate schema for a shape directly, 
        # or mock the public method. _shape_to_schema is internal but we can call it.
        # It needs definitions dict.
        definitions = {}
        schema = generator._shape_to_schema(shape_id, definitions)
        print(f"\nShape: {shape_id} ({mock_shapes[shape_id].type})")
        print(json.dumps(schema, indent=2))
        
        # Validation checks
        stype = schema.get("type")
        dtype = mock_shapes[shape_id].type
        
        if dtype in ["float", "double", "bigDecimal"]:
             if stype == "number":
                 print("SUCCESS: Mapped to number")
             else:
                 print(f"FAILURE: Mapped to {stype} (expected number)")
                 
        if dtype in ["bigInteger"]:
             if stype == "integer":
                 print("SUCCESS: Mapped to integer")
             else:
                 print(f"FAILURE: Mapped to {stype} (expected integer)")
                 
        if dtype == "blob":
             if stype == "string":
                 print("SUCCESS: Mapped to string (for base64)")
             else:
                 print(f"FAILURE: Mapped to {stype}")

if __name__ == "__main__":
    run_test()
