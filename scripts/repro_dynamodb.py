
import sys
import os
import json
from unittest.mock import MagicMock

# Adjust path to import src
sys.path.append(os.path.join(os.getcwd(), "src"))

from aws_cli_mcp.smithy.schema_generator import SchemaGenerator

# Mock the smithy model loader/interface since we might not have the full model loaded here easily
# effectively we want to see how SchemaGenerator handles a structure that looks like AttributeValue.
# But SchemaGenerator relies on `smithy_model` (a complex object).

# Instead, let's try to use the actual app context if possible, or just look at the code.
# The `server.py` initializes the app. Let's try to tap into the real catalog if it's available.

try:
    from aws_cli_mcp.app import get_app_context
    ctx = get_app_context()
    schema_generator = ctx.schema_generator
    catalog = ctx.catalog
    
    # Verify we can find DynamoDB PutItem
    entry = catalog.find_operation("dynamodb", "PutItem")
    
    if not entry:
        print("Could not find DynamoDB PutItem in catalog")
        sys.exit(1)
        
    print(f"Found operation: {entry.operation_shape_id}")
    
    schema = schema_generator.generate_operation_input_schema(entry.operation_shape_id)
    # print("Generated Schema for PutItem:", json.dumps(schema, indent=2))
    
    # Locate nested AttributeValue schema to confirm it's now an object (or string currently)
    # Structure is usually: PutItemInput -> Item (Map) -> AttributeValue (Union)
    
    props = schema.get("properties", {})
    item_schema = props.get("Item")
    
    if item_schema:
        print("\nSchema for 'Item':")
        # Item is a Map, so check additionalProperties
        attr_value_schema = item_schema.get("additionalProperties")
        print(json.dumps(attr_value_schema, indent=2))
        
        # Check if it has properties S, N, etc.
        print("AttributeValue properties:", list(attr_value_schema.get("properties", {}).keys()))
        
        props = attr_value_schema.get("properties", {})
        
        if "S" in props:
             print("S type:", props["S"])
        
        if "BOOL" in props:
             print("BOOL type:", props["BOOL"])
             
        if "NULL" in props:
             print("NULL type:", props["NULL"])

        if props.get("BOOL", {}).get("type") == "boolean":
             print("\nSUCCESS: BOOL is boolean.")
        else:
             print("\nFAILURE: BOOL is NOT boolean.")

        if props.get("NULL", {}).get("type") == "boolean":
             print("\nSUCCESS: NULL is boolean.")
        else:
             print("\nFAILURE: NULL is NOT boolean.")
    else:
        print("\n'Item' property not found in schema!")

except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"Error: {e}")
