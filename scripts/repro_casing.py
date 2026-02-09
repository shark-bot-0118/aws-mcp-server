
import sys
import os

# Mock the _snake_case function from executor.py
def _snake_case_current(name: str) -> str:
    result = ""
    for i, char in enumerate(name):
        if char.isupper() and i != 0:
            result += "_"
        result += char.lower()
    return result

try:
    from botocore import xform_name
    HAS_BOTOCORE = True
except ImportError:
    HAS_BOTOCORE = False
    xform_name = None

def run_test():
    test_cases = [
        "DescribeDBInstances",
        "DescribeOrderableDBInstanceOptions",
        "DescribeCertificates", # Control case
        "DescribeAccountAttributes", # Control case
        "ListBuckets"
    ]
    
    print(f"{'Input':<40} | {'Current':<40} | {'BotoCore (Target)':<40}")
    print("-" * 125)
    
    for case in test_cases:
        current = _snake_case_current(case)
        boto = xform_name(case) if HAS_BOTOCORE else "N/A"
        
        print(f"{case:<40} | {current:<40} | {boto:<40}")
        
    if HAS_BOTOCORE:
        print("\nVerification:")
        if xform_name("DescribeDBInstances") == "describe_db_instances":
             print("SUCCESS: botocore.xform_name produces 'describe_db_instances'")
        else:
             print(f"FAILURE: botocore.xform_name produces '{xform_name('DescribeDBInstances')}'")

if __name__ == "__main__":
    run_test()
