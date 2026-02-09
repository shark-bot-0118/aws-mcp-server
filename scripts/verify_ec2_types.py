import sys
import os
import yaml
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from aws_cli_mcp.policy.models import PolicyConfig
from aws_cli_mcp.policy.engine import PolicyEngine
from aws_cli_mcp.domain.operations import OperationRef

def test_ec2_types_policy():
    # Load policy.yaml
    policy_path = Path(__file__).parent.parent / "policy.yaml"
    with open(policy_path) as f:
        config_data = yaml.safe_load(f)
    
    config = PolicyConfig(**config_data)
    engine = PolicyEngine(config)

    print("=== Testing EC2 DescribeInstanceTypes Policy ===")
    
    # Test DescribeInstanceTypes
    op = OperationRef(service="ec2", operation="DescribeInstanceTypes")
    decision = engine.evaluate(op, {})
    print(f"ec2:DescribeInstanceTypes -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: ec2:DescribeInstanceTypes should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    print("\nSUCCESS: DescribeInstanceTypes is allowed")

if __name__ == "__main__":
    test_ec2_types_policy()
