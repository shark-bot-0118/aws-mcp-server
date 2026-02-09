"""Tests for idp_config protected resource validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aws_cli_mcp.auth.idp_config import (
    _normalize_scope_list,
    _parse_idp_config,
    _parse_oauth_proxy_config,
    _parse_role_mapping,
    _process_env_vars,
    _project_root,
    _substitute_env_vars,
    load_idp_config,
)


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


def test_substitute_and_process_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_VAR", "value-1")
    assert _substitute_env_vars("${TEST_VAR}") == "value-1"
    assert _substitute_env_vars("$TEST_VAR") == "value-1"
    assert _substitute_env_vars("$MISSING_VAR") == "$MISSING_VAR"
    processed = _process_env_vars({"x": ["$TEST_VAR", {"y": "${MISSING}"}]})
    assert processed["x"][0] == "value-1"
    assert processed["x"][1]["y"] == "${MISSING}"


def test_project_root_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "exists", lambda self: False)
    root = _project_root()
    assert root.exists() is False


def test_parse_idp_config_audience_and_algorithms() -> None:
    parsed = _parse_idp_config(
        {
            "name": "idp",
            "issuer": "https://issuer.example.com",
            "audience": ["aud-a", "aud-b"],
            "allowed_algorithms": "RS256,ES256",
        }
    )
    assert parsed.get_audience_set() == {"aud-a", "aud-b"}
    assert parsed.allowed_algorithms == ("RS256", "ES256")


def test_parse_role_mapping_valid_and_invalid_claims() -> None:
    parsed = _parse_role_mapping(
        {
            "account_id": "111111111111",
            "role_arn": "arn:aws:iam::111111111111:role/TestRole",
            "groups": "dev",
        }
    )
    assert parsed.groups == ("dev",)

    parsed2 = _parse_role_mapping(
        {
            "account_id": "111111111111",
            "role_arn": "arn:aws:iam::111111111111:role/TestRole",
            "groups": ["a", "b"],
        }
    )
    assert parsed2.groups == ("a", "b")

    with pytest.raises(ValueError, match="claims must be a dict"):
        _parse_role_mapping(
            {
                "account_id": "111111111111",
                "role_arn": "arn:aws:iam::111111111111:role/TestRole",
                "claims": ["bad"],
            }
        )


def test_normalize_scope_list_validation() -> None:
    assert _normalize_scope_list(["openid", " profile "], "x") == ("openid", "profile")
    with pytest.raises(ValueError, match="must be a list"):
        _normalize_scope_list("openid", "x")
    with pytest.raises(ValueError, match="only strings"):
        _normalize_scope_list(["openid", 1], "x")
    with pytest.raises(ValueError, match="empty scope"):
        _normalize_scope_list([""], "x")


def test_parse_oauth_proxy_config_validation_errors() -> None:
    idps = [_parse_idp_config({"name": "idp", "issuer": "https://iss", "audience": "aud"})]

    cfg = _parse_oauth_proxy_config({}, idps)
    assert cfg.enabled is False

    cfg2 = _parse_oauth_proxy_config(
        {
            "oauth_proxy": {
                "enabled": True,
                "upstream_client_id": "cid",
                "upstream_token_auth_method": "none",
                "upstream_client_secret": "   ",
            }
        },
        idps,
    )
    assert cfg2.upstream_client_secret is None

    with pytest.raises(ValueError, match="redirect_path must start"):
        _parse_oauth_proxy_config(
            {
                "oauth_proxy": {
                    "enabled": True,
                    "upstream_client_id": "cid",
                    "redirect_path": "oauth/callback",
                }
            },
            idps,
        )

    with pytest.raises(ValueError, match="must be one of"):
        _parse_oauth_proxy_config(
            {
                "oauth_proxy": {
                    "enabled": True,
                    "upstream_client_id": "cid",
                    "upstream_token_auth_method": "invalid",
                }
            },
            idps,
        )

    with pytest.raises(ValueError, match="upstream_client_id is required"):
        _parse_oauth_proxy_config({"oauth_proxy": {"enabled": True}}, idps)

    with pytest.raises(ValueError, match="upstream_client_secret is required"):
        _parse_oauth_proxy_config(
            {
                "oauth_proxy": {
                    "enabled": True,
                    "upstream_client_id": "cid",
                    "upstream_token_auth_method": "client_secret_post",
                }
            },
            idps,
        )

    with pytest.raises(ValueError, match="auth_code_ttl_seconds must be positive"):
        _parse_oauth_proxy_config(
            {
                "oauth_proxy": {
                    "enabled": True,
                    "upstream_client_id": "cid",
                    "auth_code_ttl_seconds": 0,
                }
            },
            idps,
        )

    with pytest.raises(ValueError, match="transaction_ttl_seconds must be positive"):
        _parse_oauth_proxy_config(
            {
                "oauth_proxy": {
                    "enabled": True,
                    "upstream_client_id": "cid",
                    "transaction_ttl_seconds": 0,
                }
            },
            idps,
        )

    with pytest.raises(ValueError, match="not found in configured idps"):
        _parse_oauth_proxy_config(
            {
                "oauth_proxy": {
                    "enabled": True,
                    "upstream_client_id": "cid",
                    "upstream_idp": "missing",
                }
            },
            idps,
        )


def test_load_idp_config_error_branches(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_idp_config(tmp_path / "missing.yaml")

    data = _base_config()
    data["idps"] = []
    with pytest.raises(ValueError, match="At least one IdP must be configured"):
        load_idp_config(_write_config(tmp_path, data))

    data = _base_config()
    data["role_mappings"] = []
    with pytest.raises(ValueError, match="At least one role mapping must be configured"):
        load_idp_config(_write_config(tmp_path, data))

    data = _base_config()
    data["protected_resource"]["resource"] = ""
    with pytest.raises(ValueError, match="resource URL is required"):
        load_idp_config(_write_config(tmp_path, data))

    data = _base_config()
    data["protected_resource"]["resource"] = "   "
    with pytest.raises(ValueError, match="resource URL is required"):
        load_idp_config(_write_config(tmp_path, data))


def test_multi_idp_lookup_returns_none_when_not_found(tmp_path: Path) -> None:
    cfg = load_idp_config(_write_config(tmp_path, _base_config()))
    assert cfg.get_idp_by_name("test-idp") is not None
    assert cfg.get_idp_by_issuer("https://missing.example.com") is None
    assert cfg.get_idp_by_name("missing-name") is None
