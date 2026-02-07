"""Tests for idp_config protected resource validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aws_cli_mcp.auth.idp_config import load_idp_config


def _base_config() -> dict:
    return {
        "idps": [
            {
                "name": "test-idp",
                "issuer": "https://login.example.com",
                "audience": "api://test-app",
            }
        ],
        "role_mappings": [
            {
                "account_id": "111111111111",
                "role_arn": "arn:aws:iam::111111111111:role/TestRole",
            }
        ],
        "protected_resource": {
            "resource": "https://mcp.example.com/mcp",
            "scopes_supported": ["openid", "profile", "offline_access"],
        },
    }


def _write_config(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "idp_config.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_load_idp_config_rejects_resource_list(tmp_path: Path) -> None:
    data = _base_config()
    data["protected_resource"]["resource"] = ["https://mcp.example.com/mcp"]
    path = _write_config(tmp_path, data)

    with pytest.raises(ValueError, match="must be a string"):
        load_idp_config(path)


def test_load_idp_config_accepts_auto_resource(tmp_path: Path) -> None:
    data = _base_config()
    data["protected_resource"]["resource"] = "auto"
    path = _write_config(tmp_path, data)

    config = load_idp_config(path)
    assert config.protected_resource.resource == "auto"


def test_load_idp_config_rejects_non_string_scope(tmp_path: Path) -> None:
    data = _base_config()
    data["protected_resource"]["scopes_supported"] = ["openid", 123]
    path = _write_config(tmp_path, data)

    with pytest.raises(ValueError, match="contain only strings"):
        load_idp_config(path)


def test_load_idp_config_accepts_oauth_proxy_block(tmp_path: Path) -> None:
    data = _base_config()
    data["oauth_proxy"] = {
        "enabled": True,
        "upstream_idp": "test-idp",
        "upstream_client_id": "proxy-client-id",
        "upstream_client_secret": "proxy-client-secret",
        "upstream_scopes": ["openid", "profile", "api://test-app/aws.execute"],
        "redirect_path": "/oauth/callback",
    }
    path = _write_config(tmp_path, data)

    config = load_idp_config(path)
    assert config.oauth_proxy.enabled is True
    assert config.oauth_proxy.upstream_idp == "test-idp"
    assert config.oauth_proxy.upstream_client_id == "proxy-client-id"


def test_load_idp_config_accepts_oauth_proxy_without_client_secret(tmp_path: Path) -> None:
    data = _base_config()
    data["oauth_proxy"] = {
        "enabled": True,
        "upstream_client_id": "proxy-client-id",
        "upstream_token_auth_method": "none",
    }
    path = _write_config(tmp_path, data)

    config = load_idp_config(path)
    assert config.oauth_proxy.enabled is True
    assert config.oauth_proxy.upstream_client_secret is None
    assert config.oauth_proxy.upstream_token_auth_method == "none"


def test_load_idp_config_rejects_secret_post_without_secret(tmp_path: Path) -> None:
    data = _base_config()
    data["oauth_proxy"] = {
        "enabled": True,
        "upstream_client_id": "proxy-client-id",
        "upstream_token_auth_method": "client_secret_post",
    }
    path = _write_config(tmp_path, data)

    with pytest.raises(ValueError, match="upstream_token_auth_method=client_secret_post"):
        load_idp_config(path)
