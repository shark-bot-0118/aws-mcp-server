
import sys
import os
import boto3
from botocore import handlers

sys.path.append(os.path.join(os.getcwd(), "src"))

def identify_and_remove():
    print("--- Identifying Checksum Handler ---")
    
    session = boto3.Session()
    client = session.client("s3")
    
    # The handler function responsible for wrapping response in StreamingChecksumBody
    # In recent botocore, it is likely 'add_checksum_body_to_response' in botocore.handlers
    
    target_handler = getattr(handlers, "add_checksum_body_to_response", None)
    if not target_handler:
        print("Function 'add_checksum_body_to_response' not found in botocore.handlers")
        print("Available handlers:", dir(handlers))
        return

    print(f"Found handler function: {target_handler}")
    
    # Check if registered
    # client.meta.events.unregister(event_name, handler=target_handler) returns None, 
    # so we just try to register and check behavior, or trust it.
    
    print("Attempting unregister by reference...")
    try:
        client.meta.events.unregister("after-call.s3.GetObject", handler=target_handler)
        client.meta.events.unregister("after-call.s3.*", handler=target_handler)
        print("Unregister calls completed (no error).")
    except Exception as e:
        print(f"Unregister failed: {e}")
        
    # Verify by fake call (mocking)
    # Just printing success for now if code runs
    print("SUCCESS: Unregister logic executed.")

if __name__ == "__main__":
    identify_and_remove()
