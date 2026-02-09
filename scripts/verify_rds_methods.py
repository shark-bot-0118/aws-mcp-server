
import boto3
import sys

try:
    client = boto3.client("rds", region_name="us-east-1")
    methods = dir(client)
    
    print("Searching for 'describe_db_instances' in RDS client methods...")
    
    target = "describe_db_instances"
    
    if target in methods:
        print(f"FOUND: '{target}' exists.")
    else:
        print(f"MISSING: '{target}' does NOT exist.")
        
    if incorrect in methods:
        print(f"FOUND: '{incorrect}' exists.")
    else:
        print(f"MISSING: '{incorrect}' does NOT exist.")

    # List similar methods for clarity
    print("\nSimilar methods found:")
    for m in methods:
        if "describe" in m and "instance" in m:
            print(f"- {m}")
            
except Exception as e:
    print(f"Error: {e}")
