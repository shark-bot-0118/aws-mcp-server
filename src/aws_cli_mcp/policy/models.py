"""Policy configuration models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


def _ensure_list(v: Any) -> list:
    """Convert None to empty list, pass through lists."""
    if v is None:
        return []
    return v


class PolicyDefaults(BaseModel):
    deny_destructive: bool = Field(default=True)
    require_approval_for_destructive: bool = Field(default=True)
    require_approval_for_risk: list[str] = Field(default_factory=list)

    @field_validator("require_approval_for_risk", mode="before")
    @classmethod
    def _validate_require_approval_for_risk(cls, v: Any) -> list:
        return _ensure_list(v)


class PolicyRules(BaseModel):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)

    @field_validator("allow", "deny", mode="before")
    @classmethod
    def _validate_lists(cls, v: Any) -> list:
        return _ensure_list(v)


class RequiredTag(BaseModel):
    key: str
    pattern: str


class ApprovalSettings(BaseModel):
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class ServicePolicy(BaseModel):
    allowlist: list[str] = Field(default_factory=list)
    denylist: list[str] = Field(default_factory=list)

    @field_validator("allowlist", "denylist", mode="before")
    @classmethod
    def _validate_lists(cls, v: Any) -> list:
        return _ensure_list(v)


class PolicyConfig(BaseModel):
    version: int = Field(default=1)
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    rules: PolicyRules = Field(default_factory=PolicyRules)
    destructive_patterns: list[str] = Field(default_factory=list)
    risk_patterns: dict[str, list[str]] = Field(default_factory=dict)
    required_tags: list[RequiredTag] = Field(default_factory=list)
    approval: ApprovalSettings = Field(default_factory=ApprovalSettings)
    services: ServicePolicy = Field(default_factory=ServicePolicy)

    @field_validator("destructive_patterns", "required_tags", mode="before")
    @classmethod
    def _validate_lists(cls, v: Any) -> list:
        return _ensure_list(v)

    @field_validator("risk_patterns", mode="before")
    @classmethod
    def _validate_risk_patterns(cls, v: Any) -> dict:
        if v is None:
            return {}
        # Also ensure nested lists are not None
        if isinstance(v, dict):
            return {k: _ensure_list(val) for k, val in v.items()}
        return v

    @classmethod
    def from_yaml(cls, data: dict[str, object]) -> "PolicyConfig":
        return cls.model_validate(data)
