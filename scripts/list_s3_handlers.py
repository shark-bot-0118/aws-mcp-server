
import sys
import os
import boto3
from botocore.hooks import HierarchicalEmitter

sys.path.append(os.path.join(os.getcwd(), "src"))

def list_handlers():
    print("--- Listing S3 Client Event Handlers ---")
    
    session = boto3.Session()
    client = session.client("s3")
    
    # Inspect emitter
    emitter = client.meta.events
    
    # We are looking for 'after-call' or 'after-call.s3.GetObject'
    print("\n[after-call.s3.GetObject] Handlers:")
    try:
        # Access internal lookup (impl detail, but valid for inspection)
        # Emitter structure varies by version.
        if hasattr(emitter, "_lookup_cache"):
             # It's a HierarchicalEmitter
             # But we can just emit a fake event and see response? No.
             pass
             
        # Traversing internal dict
        for key in emitter._lookup_cache:
            if "s3" in str(key):
                print(f"  Key: {key}")

        # Or accessing _handlers directly
        if hasattr(emitter, "_handlers"):
             handlers = emitter._handlers
             # It's a tree.
             # We want specific event.
             handlers_list = emitter.get_handlers("after-call.s3.GetObject")
             for h in handlers_list:
                 print(f"  Handler: {h} (Name: {getattr(h, '__name__', 'Unknown')})")

    except Exception as e:
        print(f"Inspection failed: {e}")

if __name__ == "__main__":
    list_handlers()
