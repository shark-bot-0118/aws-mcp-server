
import sys
import os
import json
import datetime
import shutil
from pathlib import Path

sys.path.append(os.path.join(os.getcwd(), "src"))

from aws_cli_mcp.audit.artifacts import ArtifactStore

def test_audit_serialization():
    print("--- Verify ArtifactStore Serialization ---")
    tmp_dir = Path("./tmp_audit_test")
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
        
    store = ArtifactStore(str(tmp_dir))
    
    payload = {
        "timestamp": datetime.datetime(2023, 1, 1, 12, 0, 0),
        "binary": b"some bytes",
        "nested": {
            "more_bytes": b"nested"
        }
    }
    
    print("Attempting to write_json with datetime and bytes...")
    try:
        record = store.write_json("test_record", payload, prefix="test")
        print(f"[SUCCESS] Artifact created: {record.location}")
        
        # Verify content on disk
        with open(record.location, "r") as f:
            content = json.load(f)
            print(f"  Content loaded: {content}")
            
        # expected: timestamp as string, binary as string (from json_default)
        if isinstance(content["timestamp"], str) and isinstance(content["binary"], str):
            print("  [PASS] Datetime and bytes serialized correctly.")
        else:
            print("  [FAIL] Content types unexpected.")
            
    except Exception as e:
        print(f"[FAIL] write_json crashed: {e}")
    finally:
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir)

if __name__ == "__main__":
    test_audit_serialization()
