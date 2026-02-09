
import sys
import os
import boto3

sys.path.append(os.path.join(os.getcwd(), "src"))

def try_unregister():
    print("--- Brute-forcing Handler Unregister ---")
    
    session = boto3.Session()
    client = session.client("s3")
    
    # Common handler unique IDs for checksums
    candidates = [
        "add_checksum_body_to_response",
        "inject_checksum_body",
        "validate_response_checksum",
        "handle_checksum_body"
    ]
    
    events = [
        "after-call.s3.GetObject",
        "after-call.s3.*",
        "after-call.*"
    ]
    
    for event in events:
        for cid in candidates:
            try:
                # boto3 unregister returns None usually, but let's try
                client.meta.events.unregister(event, unique_id=cid)
                print(f"Unregistered '{cid}' from '{event}' (No error raised)")
                
                # Verify if it persists? Hard without knowing if it was there.
            except Exception as e:
                print(f"Error unregistering {cid}: {e}")

    # Now let's try to verify if GetObject returns a simple StreamingBody
    # We need a bucket/key that exists (user provided one)
    # But since we don't have creds to actually run it successfully in this script (maybe),
    # we just check if we can inspect registered handlers properly?
    
    # Let's inspect handlers via the internal list if possible now
    try:
        emitter = client.meta.events
        # Deeper inspection
        import botocore.hooks
        if isinstance(emitter, botocore.hooks.HierarchicalEmitter):
             pass # We can't easy see keys
    except:
        pass

if __name__ == "__main__":
    try_unregister()
