import sys
import os
import yaml
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from aws_cli_mcp.policy.models import PolicyConfig
from aws_cli_mcp.policy.engine import PolicyEngine
from aws_cli_mcp.domain.operations import OperationRef

def test_s3_policy():
    # Load policy.yaml
    policy_path = Path(__file__).parent.parent / "policy.yaml"
    with open(policy_path) as f:
        config_data = yaml.safe_load(f)
    
    config = PolicyConfig(**config_data)
    engine = PolicyEngine(config)

    print("Testing s3:DeleteObject (Destructive, No Tags supported)...")
    # Test DeleteObject (Destructive, No Tags supported)
    op = OperationRef(service="s3", operation="DeleteObject")
    decision = engine.evaluate(op, {"Bucket": "test", "Key": "test"})
    
    print(f"Decision: Allowed={decision.allowed}, Reasons={decision.reasons}")
    if not decision.allowed:
        print("FAILED: s3:DeleteObject should be allowed")
        # We expect this to fail initially
    else:
        print("PASSED: s3:DeleteObject is allowed")

    print("\nTesting s3:CreateBucket...")
    # Test CreateBucket
    op = OperationRef(service="s3", operation="CreateBucket")
    decision = engine.evaluate(op, {"Bucket": "test-bucket"})
    print(f"Decision: Allowed={decision.allowed}, Reasons={decision.reasons}")
    if not decision.allowed:
        print("FAILED: s3:CreateBucket should be allowed")
    else:
        print("PASSED: s3:CreateBucket is allowed")

if __name__ == "__main__":
    test_s3_policy()
