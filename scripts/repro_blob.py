
import boto3
from botocore.exceptions import ParamValidationError

def test_blob_handling():
    # KMS encrypt expects Plaintext as blob (bytes)
    # We won't actually call AWS, but we can check if validation fails before sending
    # or if we can use a service that doesn't need auth for validation? 
    # Actually client-side validation raises ParamValidationError if type is wrong.
    
    client = boto3.client("kms", region_name="us-east-1")
    
    print("Testing Blob input as String:")
    try:
        # Pass string instead of bytes
        client.encrypt(KeyId="alias/test", Plaintext="some text")
        print("Function returned (unexpectedly success or auth error)")
    except ParamValidationError as e:
        print(f"Validation Error (Expected): {e}")
    except Exception as e:
        print(f"Other Error: {type(e).__name__}: {e}")
        # If it's not validation error, it might have accepted string?

    print("\nTesting Blob input as Bytes:")
    try:
         # Pass bytes
         client.encrypt(KeyId="alias/test", Plaintext=b"some text")
         print("Function returned (likely clean execution until auth failure)")
    except ParamValidationError as e:
         print(f"Validation Error: {e}")
    except Exception as e:
         print(f"Other Error: {type(e).__name__} (likely Auth/Net): {e}")

if __name__ == "__main__":
    test_blob_handling()
