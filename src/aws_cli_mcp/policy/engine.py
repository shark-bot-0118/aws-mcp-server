"""Policy evaluation engine."""

from __future__ import annotations

import re
from dataclasses import dataclass

from aws_cli_mcp.domain.operations import OperationRef
from aws_cli_mcp.policy.models import PolicyConfig, RequiredTag


@dataclass
class PolicyDecision:
    allowed: bool
    require_approval: bool
    risk: str | None
    reasons: list[str]


class PolicyEngine:
    def __init__(self, config: PolicyConfig) -> None:
        self._config = config
        self._allow_patterns = [re.compile(pat) for pat in config.rules.allow]
        self._deny_patterns = [re.compile(pat) for pat in config.rules.deny]
        self._destructive_patterns = [re.compile(pat) for pat in config.destructive_patterns]
        self._risk_patterns = {
            risk: [re.compile(pat) for pat in pats]
            for risk, pats in config.risk_patterns.items()
        }
        self._service_allowlist = frozenset(s.lower() for s in config.services.allowlist)
        self._service_denylist = frozenset(s.lower() for s in config.services.denylist)

    def evaluate(self, operation: OperationRef, params: dict[str, object]) -> PolicyDecision:
        reasons: list[str] = []
        key = operation.key
        if not self.is_service_allowed(operation.service):
            reasons.append("Service is not allowlisted")
            return PolicyDecision(False, False, self._risk_for_operation(operation), reasons)

        deny_match = self._matches(self._deny_patterns, key)
        if deny_match:
            reasons.append(f"Denied by policy rule: {deny_match}")
            return PolicyDecision(False, False, self._risk_for_operation(operation), reasons)

        allow_match = self._matches(self._allow_patterns, key)
        if self._allow_patterns and not allow_match:
            reasons.append("Operation is not allowlisted")
            return PolicyDecision(False, False, self._risk_for_operation(operation), reasons)

        destructive = self._is_destructive(operation)
        if destructive and self._config.defaults.deny_destructive and not allow_match:
            reasons.append("Destructive operations require explicit allow rule")
            return PolicyDecision(False, False, self._risk_for_operation(operation), reasons)

        if self._config.required_tags:
            if not self._has_required_tags(operation, params, self._config.required_tags):
                reasons.append("Required tags missing or invalid")
                return PolicyDecision(False, False, self._risk_for_operation(operation), reasons)

        risk = self._risk_for_operation(operation)
        require_approval = False
        if destructive and self._config.defaults.require_approval_for_destructive:
            require_approval = True
        if risk and risk in self._config.defaults.require_approval_for_risk:
            require_approval = True

        return PolicyDecision(True, require_approval, risk, reasons)

    def is_operation_allowed(self, operation: OperationRef) -> bool:
        key = operation.key
        if not self.is_service_allowed(operation.service):
            return False
        if self._matches(self._deny_patterns, key):
            return False
        if self._allow_patterns and not self._matches(self._allow_patterns, key):
            return False
        return True

    def is_service_allowed(self, service: str) -> bool:
        service_key = service.lower()
        if not self._service_allowlist:
            return False
        if service_key not in self._service_allowlist:
            return False
        if service_key in self._service_denylist:
            return False
        return True

    def risk_for_operation(self, operation: OperationRef) -> str | None:
        return self._risk_for_operation(operation)

    @property
    def approval_ttl_seconds(self) -> int:
        return self._config.approval.ttl_seconds

    def _matches(self, patterns: list[re.Pattern[str]], key: str) -> str | None:
        for pattern in patterns:
            if pattern.search(key):
                return pattern.pattern
        return None

    def _is_destructive(self, operation: OperationRef) -> bool:
        for pattern in self._destructive_patterns:
            if pattern.search(operation.operation):
                return True
        return False

    def _risk_for_operation(self, operation: OperationRef) -> str | None:
        for risk, patterns in self._risk_patterns.items():
            if any(pattern.search(operation.operation) for pattern in patterns):
                return risk
        return None

    def _has_required_tags(self, operation: OperationRef, params: dict[str, object], required: list[RequiredTag]) -> bool:
        tags = _extract_tags(params)
        if not tags:
            # If no tags are being applied:
            # - If the operation is destructive (likely a Create/Update), we MUST enforce tags.
            # - If the operation is read-only, we allow it (as read ops typically don't accept tags).
            if self._is_destructive(operation):
                return False
            return True
        
        for required_tag in required:
            matched = False
            for tag in tags:
                key = tag.get("Key") or tag.get("key")
                value = tag.get("Value") or tag.get("value")
                if key == required_tag.key and value is not None:
                    if re.fullmatch(required_tag.pattern, str(value)):
                        matched = True
                        break
            if not matched:
                return False
        return True


def _extract_tags(params: dict[str, object]) -> list[dict[str, object]]:
    tags: list[dict[str, object]] = []
    direct = params.get("Tags")
    if isinstance(direct, list):
        tags.extend([tag for tag in direct if isinstance(tag, dict)])

    specs = params.get("TagSpecifications")
    if isinstance(specs, list):
        for spec in specs:
            if isinstance(spec, dict):
                nested = spec.get("Tags")
                if isinstance(nested, list):
                    tags.extend([tag for tag in nested if isinstance(tag, dict)])
    return tags
