
import sys
import os
import json
import decimal
import io

sys.path.append(os.path.join(os.getcwd(), "src"))

from aws_cli_mcp.tools.base import result_from_payload

class MockStreamingBody:
    def __init__(self, data: bytes):
        self._data = data
    
    def read(self):
        return self._data
        
    def __str__(self):
        return "<botocore.response.StreamingBody object at ...>"

def survey():
    print("--- Surveying Serialization ---")
    
    test_cases = {
        "Decimal": decimal.Decimal("10.5"),
        "Bytes": b"some binary data",
        "StreamingBody (Mock)": MockStreamingBody(b"stream content")
    }
    
    for name, val in test_cases.items():
        payload = {"key": val}
        print(f"\nTesting {name}:")
        try:
            res = result_from_payload(payload)
            print(f"  Result: {res.content}")
        except Exception as e:
            print(f"  FAILED: {e}")

if __name__ == "__main__":
    survey()
