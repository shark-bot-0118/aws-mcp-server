"""Policy loader for policy.yaml."""

from __future__ import annotations

from pathlib import Path

import yaml

from aws_cli_mcp.policy.models import PolicyConfig


def load_policy(path: str) -> PolicyConfig:
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")
    with policy_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return PolicyConfig.from_yaml(data)
