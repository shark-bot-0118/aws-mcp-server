from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aws_cli_mcp.policy.loader import load_policy


def test_load_policy_file_not_found(tmp_path: Path) -> None:
    missing = tmp_path / "missing-policy.yaml"
    with pytest.raises(FileNotFoundError):
        load_policy(str(missing))


def test_load_policy_success(tmp_path: Path) -> None:
    policy = {
        "services": {"allowlist": ["s3"], "denylist": []},
        "destructive_patterns": ["^s3:Delete.*$"],
        "require_confirmation": True,
        "auto_approve_patterns": [],
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")

    loaded = load_policy(str(path))
    assert loaded.services.allowlist == ["s3"]
