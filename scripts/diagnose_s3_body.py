
import sys
import os
import boto3

sys.path.append(os.path.join(os.getcwd(), "src"))

from aws_cli_mcp.execution.aws_client import get_client

def diagnose_s3():
    print("--- Diagnosing S3 Body State ---")
    
    service = "s3"
    payload = {
        "Bucket": "test-26-0129",
        "Key": "test-data.txt"
    }

    try:
        client = get_client(service, None, None)
        print(f"Calling GetObject...")
        response = client.get_object(**payload)
        
        body = response.get("Body")
        if not body:
            print("No Body returned.")
            return
            
        print(f"Body Type: {type(body)}")
        
        # Check position
        if hasattr(body, "tell"):
            try:
                print(f"Body.tell(): {body.tell()}")
            except Exception as e:
                print(f"Body.tell() failed: {e}")
                
        # Inspect _raw_stream
        if hasattr(body, "_raw_stream"):
            raw = body._raw_stream
            print(f"Raw Stream Type: {type(raw)}")
            if hasattr(raw, "tell"):
                 try:
                     print(f"Raw.tell(): {raw.tell()}")
                 except Exception as e:
                     print(f"Raw.tell() failed: {e}")
            if hasattr(raw, "closed"):
                print(f"Raw.closed: {raw.closed}")
            if hasattr(raw, "isclosed"): # urllib3
                print(f"Raw.isclosed(): {raw.isclosed()}")

        # Attempt Read 1: Normal
        print("\n--- Attempt 1: Normal Read ---")
        try:
             content = body.read()
             print(f"Read length: {len(content)}")
             if len(content) > 0:
                 print(f"Preview: {content[:20]}")
        except Exception as e:
            print(f"Read failed: {e}")

        # Attempt 2: Seek & Read
        print("\n--- Attempt 2: Seek(0) & Read ---")
        if hasattr(body, "seek"):
            try:
                body.seek(0)
                print("Seek(0) successful.")
                content = body.read()
                print(f"Read length: {len(content)}")
            except Exception as e:
                print(f"Seek/Read failed: {e}")
        
        # Attempt 3: Raw Stream Access
        print("\n--- Attempt 3: Raw Stream Read ---")
        if hasattr(body, "_raw_stream"):
             raw = body._raw_stream
             if hasattr(raw, "read"):
                 try:
                     # Some raw streams (HTTPResponse) don't support seek if consumed.
                     # But we check anyway.
                     raw_content = raw.read()
                     print(f"Raw Read length: {len(raw_content)}")
                 except Exception as e:
                     print(f"Raw Read failed: {e}")

    except Exception as e:
        print(f"Diagnosis failed: {e}")

if __name__ == "__main__":
    diagnose_s3()
