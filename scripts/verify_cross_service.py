
import sys
import os
import json
import decimal
import datetime
import io

sys.path.append(os.path.join(os.getcwd(), "src"))

from aws_cli_mcp.app import get_app_context
from aws_cli_mcp.execution.executor import _materialize_response
from aws_cli_mcp.tools.base import result_from_payload

# Mock for StreamingBody
class MockStreamingBody:
    def __init__(self, data: bytes):
        self._raw_stream = io.BytesIO(data)
    def read(self, amt=None):
        return self._raw_stream.read(amt)

def verify_cross_service():
    print("--- Cross-Service Verification ---")
    
    # 1. DynamoDB: Decimal
    print("\n[DynamoDB] Testing Decimal Serialization...")
    ddb_response = {
        "Item": {
            "PK": "USER#123",
            "Balance": decimal.Decimal("100.50"),
            "Age": decimal.Decimal("30")
        }
    }
    # Test result_from_payload (used by tools)
    try:
        res = result_from_payload(ddb_response)
        if "100.50" in res.content and "30" in res.content:
            print("  [PASS] Decimals serialized correctly.")
        else:
             print(f"  [FAIL] Unexpected output: {res.content}")
    except Exception as e:
        print(f"  [FAIL] Error: {e}")

    # 2. RDS: Datetime
    print("\n[RDS] Testing Datetime Serialization...")
    rds_response = {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "mydb",
                "InstanceCreateTime": datetime.datetime(2023, 1, 1, 12, 0, 0)
            }
        ]
    }
    try:
        res = result_from_payload(rds_response)
        if "2023-01-01T12:00:00" in res.content:
            print("  [PASS] Datetime serialized correctly.")
        else:
             print(f"  [FAIL] Unexpected output: {res.content}")
    except Exception as e:
        print(f"  [FAIL] Error: {e}")

    # 3. Lambda: Stream (Invoke)
    print("\n[Lambda] Testing Invoke Payload Stream...")
    lambda_response = {
        "StatusCode": 200,
        "Payload": MockStreamingBody(b'{"result": "success"}')
    }
    # Test _materialize_response (used by executor)
    try:
        mat = _materialize_response(lambda_response)
        if mat["Payload"] == '{"result": "success"}':
            print("  [PASS] Stream materialized.")
            # Double check serialization
            json.dumps(mat)
            print("  [PASS] Materialized result is serializable.")
        else:
            print(f"  [FAIL] Stream content mismatch: {mat['Payload']}")
    except Exception as e:
        print(f"  [FAIL] Error: {e}")

    # 4. Schema Generation: Recursion
    print("\n[Schema] Testing Recursive Shapes (dynamodb:CreateTable)...")
    try:
        ctx = get_app_context()
        service = "dynamodb"
        operation = "CreateTable"
        entry = ctx.catalog.find_operation(service, operation)
        if entry:
            schema = ctx.schema_generator.generate_operation_input_schema(entry.operation_shape_id)
            json.dumps(schema) # Trigger circular check
            print("  [PASS] dynamodb:CreateTable schema generated and serialized.")
        else:
            print(f"  [SKIP] Operation {service}:{operation} not found.")

        # Test lambda:UpdateFunctionConfiguration (often complex)
        service = "lambda"
        operation = "UpdateFunctionConfiguration"
        print(f"[Schema] Testing {service}:{operation}...")
        entry = ctx.catalog.find_operation(service, operation)
        if entry:
            schema = ctx.schema_generator.generate_operation_input_schema(entry.operation_shape_id)
            json.dumps(schema)
            print(f"  [PASS] {service}:{operation} schema generated and serialized.")
    except Exception as e:
        print(f"  [FAIL] Schema Error: {e}")

if __name__ == "__main__":
    verify_cross_service()
