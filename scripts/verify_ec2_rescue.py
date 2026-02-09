
import sys
import os

sys.path.append(os.path.join(os.getcwd(), "src"))

from aws_cli_mcp.app import get_app_context

def verify_ec2():
    print("--- Verifying EC2 Orphan Rescue ---")
    ctx = get_app_context()
    catalog = ctx.catalog
    
    # Check for a common EC2 operation that is likely orphaned
    # Based on survey (4 attached vs 574 orphans), almost everything is an orphan.
    target_op = "RunInstances" 
    
    entry = catalog.find_operation("ec2", target_op)
    if entry:
        print(f"[SUCCESS] ec2:{target_op} found in catalog.")
        print(f"  Ref: {entry.ref}")
    else:
        print(f"[FAILURE] ec2:{target_op} NOT found in catalog.")
        
    # Check attached count vs total indexed
    ec2_ops = [op for op in catalog.list_operations() if op.ref.service == "ec2"]
    print(f"Total 'ec2' operations in Catalog: {len(ec2_ops)}")
    
    if len(ec2_ops) > 10:
        print("  Rescue logic is working (Index populated).")
    else:
        print("  Index suspiciously small. Rescue might have failed.")

if __name__ == "__main__":
    verify_ec2()
