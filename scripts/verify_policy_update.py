import sys
import os
import yaml
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from aws_cli_mcp.policy.models import PolicyConfig
from aws_cli_mcp.policy.engine import PolicyEngine
from aws_cli_mcp.domain.operations import OperationRef

def test_policy_update():
    # Load policy.yaml
    policy_path = Path(__file__).parent.parent / "policy.yaml"
    with open(policy_path) as f:
        config_data = yaml.safe_load(f)
    
    config = PolicyConfig(**config_data)
    engine = PolicyEngine(config)

    print("=== Testing S3 Policy ===")
    
    # Test DeleteObject (Destructive, No Tags supported)
    op = OperationRef(service="s3", operation="DeleteObject")
    decision = engine.evaluate(op, {"Bucket": "test", "Key": "test"})
    print(f"s3:DeleteObject -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: s3:DeleteObject should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    # Test CreateBucket
    op = OperationRef(service="s3", operation="CreateBucket")
    decision = engine.evaluate(op, {"Bucket": "test-bucket"})
    print(f"s3:CreateBucket -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: s3:CreateBucket should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    print("\n=== Testing DynamoDB Policy ===")

    # Test CreateTable
    op = OperationRef(service="dynamodb", operation="CreateTable")
    decision = engine.evaluate(op, {"TableName": "test-table"})
    print(f"dynamodb:CreateTable -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: dynamodb:CreateTable should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    # Test DeleteTable (Destructive)
    op = OperationRef(service="dynamodb", operation="DeleteTable")
    decision = engine.evaluate(op, {"TableName": "test-table"})
    print(f"dynamodb:DeleteTable -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: dynamodb:DeleteTable should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    # Test PutItem
    op = OperationRef(service="dynamodb", operation="PutItem")
    decision = engine.evaluate(op, {"TableName": "test-table", "Item": {}})
    print(f"dynamodb:PutItem -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: dynamodb:PutItem should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)
        
    # Test GetItem
    op = OperationRef(service="dynamodb", operation="GetItem")
    decision = engine.evaluate(op, {"TableName": "test-table", "Key": {}})
    print(f"dynamodb:GetItem -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: dynamodb:GetItem should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    print("\n=== Testing EC2 Policy ===")
    
    # Test StartInstances (Destructive)
    op = OperationRef(service="ec2", operation="StartInstances")
    decision = engine.evaluate(op, {"InstanceIds": ["i-1234567890abcdef0"]})
    print(f"ec2:StartInstances -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: ec2:StartInstances should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    # Test StopInstances (Destructive)
    op = OperationRef(service="ec2", operation="StopInstances")
    decision = engine.evaluate(op, {"InstanceIds": ["i-1234567890abcdef0"]})
    print(f"ec2:StopInstances -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: ec2:StopInstances should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    # Test TerminateInstances (Destructive)
    op = OperationRef(service="ec2", operation="TerminateInstances")
    decision = engine.evaluate(op, {"InstanceIds": ["i-1234567890abcdef0"]})
    print(f"ec2:TerminateInstances -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: ec2:TerminateInstances should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    # Test RunInstances (Destructive)
    op = OperationRef(service="ec2", operation="RunInstances")
    decision = engine.evaluate(op, {"ImageId": "ami-12345678", "MinCount": 1, "MaxCount": 1})
    print(f"ec2:RunInstances -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: ec2:RunInstances should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    print("\n=== Testing EC2 Volume Policy ===")

    # Test CreateVolume
    op = OperationRef(service="ec2", operation="CreateVolume")
    decision = engine.evaluate(op, {"AvailabilityZone": "us-east-1a", "Size": 10})
    print(f"ec2:CreateVolume -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: ec2:CreateVolume should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    # Test DeleteVolume (Destructive)
    op = OperationRef(service="ec2", operation="DeleteVolume")
    decision = engine.evaluate(op, {"VolumeId": "vol-1234567890abcdef0"})
    print(f"ec2:DeleteVolume -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: ec2:DeleteVolume should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    # Test AttachVolume
    op = OperationRef(service="ec2", operation="AttachVolume")
    decision = engine.evaluate(op, {"VolumeId": "vol-1234567890abcdef0", "InstanceId": "i-123", "Device": "/dev/sdf"})
    print(f"ec2:AttachVolume -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: ec2:AttachVolume should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)

    # Test DetachVolume (Destructive)
    op = OperationRef(service="ec2", operation="DetachVolume")
    decision = engine.evaluate(op, {"VolumeId": "vol-1234567890abcdef0"})
    print(f"ec2:DetachVolume -> Allowed={decision.allowed}")
    if not decision.allowed:
        print(f"FAILED: ec2:DetachVolume should be allowed. Reasons: {decision.reasons}")
        sys.exit(1)


    print("\nSUCCESS: All policy checks passed")

if __name__ == "__main__":
    test_policy_update()
