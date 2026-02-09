from unittest.mock import MagicMock

import pytest

from aws_cli_mcp.domain.operations import OperationRef
from aws_cli_mcp.policy.engine import PolicyEngine, _extract_tags
from aws_cli_mcp.policy.models import (
    PolicyConfig,
    PolicyDefaults,
    PolicyRules,
    RequiredTag,
    ServicePolicy,
)


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
        require_approval_for_risk=["high"],
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
    assert not engine.is_service_allowed("bad")  # In denylist
    assert not engine.is_service_allowed("unknown")  # Not in allowlist


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
    assert decision.destructive
    assert decision.require_approval_for_destructive
    assert decision.require_approval_for_risk
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
        deny_destructive=True, require_approval_for_destructive=True, require_approval_for_risk=[]
    )
    config_strict.required_tags = []
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
        deny_destructive=False, require_approval_for_destructive=False, require_approval_for_risk=[]
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

    # Oversized tag value -> Deny (guard against pathological regex runtime)
    decision = engine.evaluate(op, {"Tags": [{"Key": "Environment", "Value": "p" * 300}]})
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
        "TagSpecifications": [{"ResourceType": "instance", "Tags": [{"Key": "k", "Value": "v"}]}]
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


def test_is_service_allowed_handles_empty_allowlist_and_denylist_override():
    config = MagicMock(spec=PolicyConfig)
    config.rules = PolicyRules(allow=[], deny=[])
    config.services = ServicePolicy(allowlist=[], denylist=[])
    config.risk_patterns = {}
    config.destructive_patterns = []
    config.defaults = PolicyDefaults()
    config.required_tags = []
    config.approval = MagicMock(ttl_seconds=300)
    engine = PolicyEngine(config)
    assert not engine.is_service_allowed("s3")

    config2 = MagicMock(spec=PolicyConfig)
    config2.rules = PolicyRules(allow=[], deny=[])
    config2.services = ServicePolicy(allowlist=["s3"], denylist=["s3"])
    config2.risk_patterns = {}
    config2.destructive_patterns = []
    config2.defaults = PolicyDefaults()
    config2.required_tags = []
    config2.approval = MagicMock(ttl_seconds=300)
    engine2 = PolicyEngine(config2)
    assert not engine2.is_service_allowed("s3")


def test_compile_patterns_invalid_regex():
    """Invalid regex in policy patterns should raise ValueError."""
    with pytest.raises(ValueError, match="Invalid regex"):
        PolicyEngine._compile_patterns(["[invalid(regex"], "test")


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("(?<=prefix)Delete$", "look-behind"),
        (r"(a)\1", "backreferences"),
        ("(a+)+$", "nested quantifiers"),
        ("a" * 300, "exceeds 256 characters"),
    ],
)
def test_compile_patterns_rejects_unsafe_regex(pattern: str, expected: str) -> None:
    with pytest.raises(ValueError, match=expected):
        PolicyEngine._compile_patterns([pattern], "test")


def test_required_tag_invalid_regex_rejected() -> None:
    config = MagicMock(spec=PolicyConfig)
    config.rules = PolicyRules(allow=[".*"], deny=[])
    config.services = ServicePolicy(allowlist=["s3"], denylist=[])
    config.risk_patterns = {}
    config.destructive_patterns = []
    config.defaults = PolicyDefaults()
    config.required_tags = [RequiredTag(key="Environment", pattern="[invalid(")]
    config.approval = MagicMock(ttl_seconds=300)

    with pytest.raises(ValueError, match="Invalid regex in required_tag:Environment"):
        PolicyEngine(config)


def test_policy_config_normalizers_cover_none_and_non_dict_risk_patterns():
    cfg = PolicyConfig.from_yaml(
        {
            "rules": {"allow": None, "deny": None},
            "services": {"allowlist": None, "denylist": None},
            "destructive_patterns": None,
            "required_tags": None,
            "risk_patterns": None,
        }
    )
    assert cfg.rules.allow == []
    assert cfg.services.allowlist == []
    assert cfg.risk_patterns == {}

    with pytest.raises(Exception):
        PolicyConfig.from_yaml({"risk_patterns": "invalid"})
