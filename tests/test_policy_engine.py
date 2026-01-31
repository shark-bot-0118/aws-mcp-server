import pytest

from unittest.mock import MagicMock
from aws_cli_mcp.policy.engine import PolicyEngine, _extract_tags
from aws_cli_mcp.policy.models import PolicyConfig, PolicyRules, ServicePolicy, PolicyDefaults, RequiredTag
from aws_cli_mcp.domain.operations import OperationRef

@pytest.fixture
def policy_config():
    config = MagicMock(spec=PolicyConfig)
    config.rules = PolicyRules(allow=[r"^safe:.*$"], deny=[r"^.*:DenyMe$"])
    config.services = ServicePolicy(allowlist=["safe", "ec2"], denylist=["bad"])
    config.risk_patterns = {"high": [r"Delete.*"]}
    config.destructive_patterns = [r"Delete.*"]
    config.defaults = PolicyDefaults(
        deny_destructive=True,
        require_approval_for_destructive=True,
        require_approval_for_risk=["high"]
    )
    config.required_tags = []
    config.approval = MagicMock(ttl_seconds=300)
    return config

@pytest.fixture
def engine(policy_config):
    return PolicyEngine(policy_config)

def test_is_service_allowed(engine):
    assert engine.is_service_allowed("safe")
    assert engine.is_service_allowed("ec2")
    assert not engine.is_service_allowed("bad") # In denylist
    assert not engine.is_service_allowed("unknown") # Not in allowlist

def test_matches_deny(engine):
    # Deny pattern matches
    op = OperationRef("safe", "DenyMe")
    decision = engine.evaluate(op, {})
    assert not decision.allowed
    assert "Denied by policy rule" in decision.reasons[0]

def test_matches_allow(engine):
    # Allow pattern matches (safe:.*)
    op = OperationRef("safe", "ListEverything")
    decision = engine.evaluate(op, {})
    assert decision.allowed
    assert decision.risk is None

def test_no_match_denied(engine):
    # Service allowed (ec2), but operation pattern doesn't match allow list (^safe:.*)
    op = OperationRef("ec2", "DescribeInstances")
    decision = engine.evaluate(op, {})
    assert not decision.allowed
    assert "Operation is not allowlisted" in decision.reasons[0]

def test_destructive_denied(engine):
    # Destructive operation requires explicit allow rule, but even if matched by allow pattern?
    # Logic: if destructive and deny_destructive and not allow_match: Deny.
    
    # Matches allow pattern
    op = OperationRef("safe", "DeleteSomething")
    decision = engine.evaluate(op, {})
    # It matches "safe:.*", so allow_match is True.
    # deny_destructive checks "not allow_match".
    # So it should be allowed, but approval required.
    assert decision.allowed
    assert decision.require_approval
    assert decision.risk == "high"

    # Doesn't match allow pattern
    # To test "Destructive operations require explicit allow rule", we need to bypass the basic "not in allowlist" check.
    # This happens if allow_patterns is empty (meaning default deny unless specified? No, if allow patterns is empty, it skips the check at line 44)
    
    # Create a new engine with empty allow list
    config_strict = MagicMock(spec=PolicyConfig)
    config_strict.rules = PolicyRules(allow=[], deny=[])
    config_strict.services = ServicePolicy(allowlist=["ec2"], denylist=[])
    config_strict.destructive_patterns = [r"Delete.*"]
    config_strict.risk_patterns = {}
    config_strict.defaults = PolicyDefaults(
        deny_destructive=True,
        require_approval_for_destructive=True, 
        require_approval_for_risk=[]
    )
    # Mock approval to avoid AttributeError if accessed
    config_strict.approval = MagicMock(ttl_seconds=300)

    engine_strict = PolicyEngine(config_strict)
    
    op = OperationRef("ec2", "DeleteVolume")
    decision = engine_strict.evaluate(op, {})
    assert not decision.allowed
    assert "Destructive operations require explicit allow rule" in decision.reasons[0]

def test_risk_assessment(engine):
    op = OperationRef("safe", "DeleteSomething")
    assert engine.risk_for_operation(op) == "high"
    
    op = OperationRef("safe", "ListSomething")
    assert engine.risk_for_operation(op) is None

def test_approval_ttl(engine):
    assert engine.approval_ttl_seconds == 300

def test_required_tags_logic():
    # Setup engine with required tags
    config = MagicMock(spec=PolicyConfig)
    config.rules = PolicyRules(allow=[".*"], deny=[])
    config.services = ServicePolicy(allowlist=["s3"], denylist=[])
    config.risk_patterns = {}
    config.destructive_patterns = [r"Create.*"]
    config.defaults = PolicyDefaults(
        deny_destructive=False,
        require_approval_for_destructive=False,
        require_approval_for_risk=[]
    )
    # Require "Environment" tag
    config.required_tags = [RequiredTag(key="Environment", pattern="^(prod|dev)$")]
    config.approval = MagicMock(ttl_seconds=300)
    
    engine = PolicyEngine(config)

    # 1. Read-only op (not destructive) -> should allow even without tags
    op = OperationRef("s3", "ListBuckets")
    decision = engine.evaluate(op, {})
    assert decision.allowed
    
    # 2. Destructive op (Create) -> must have tags
    op = OperationRef("s3", "CreateBucket")
    
    # No tags -> Deny
    decision = engine.evaluate(op, {})
    assert not decision.allowed
    assert "Required tags missing" in decision.reasons[0]
    
    # Invalid tag value -> Deny
    decision = engine.evaluate(op, {"Tags": [{"Key": "Environment", "Value": "staging"}]})
    assert not decision.allowed
    
    # Valid tags -> Allow
    decision = engine.evaluate(op, {"Tags": [{"Key": "Environment", "Value": "prod"}]})
    assert decision.allowed

def test_extract_tags():
    # Direct list of dicts
    params = {"Tags": [{"Key": "k", "Value": "v"}]}
    assert len(_extract_tags(params)) == 1

    # TagSpecifications
    params = {
        "TagSpecifications": [
            {"ResourceType": "instance", "Tags": [{"Key": "k", "Value": "v"}]}
        ]
    }
    assert len(_extract_tags(params)) == 1
    
    # Mixed/Empty
    assert _extract_tags({}) == []
    assert _extract_tags({"Tags": "invalid"}) == []

def test_is_operation_allowed(engine):
    # Allowed
    assert engine.is_operation_allowed(OperationRef("safe", "List"))
    # Denied by service
    assert not engine.is_operation_allowed(OperationRef("bad", "List"))
    # Denied by pattern
    assert not engine.is_operation_allowed(OperationRef("safe", "DenyMe"))
    # Denied by implicit allowlist miss
    assert not engine.is_operation_allowed(OperationRef("ec2", "Describe"))
