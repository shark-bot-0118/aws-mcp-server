from __future__ import annotations

from aws_cli_mcp.auth.idp_config import (
    AuditConfig,
    IdPConfig,
    JWKSCacheConfig,
    MultiIdPConfig,
    ProtectedResourceConfig,
    RoleMappingEntry,
    SecurityConfig,
)
from aws_cli_mcp.auth.protected_resource import ProtectedResourceEndpoint


def _config_with_resource_doc() -> MultiIdPConfig:
    return MultiIdPConfig(
        idps=[IdPConfig(name="idp", issuer="https://issuer.example.com", audience="aud")],
        jwks_cache=JWKSCacheConfig(),
        security=SecurityConfig(),
        audit=AuditConfig(),
        role_mappings=[
            RoleMappingEntry(
                account_id="111111111111",
                role_arn="arn:aws:iam::111111111111:role/TestRole",
            )
        ],
        protected_resource=ProtectedResourceConfig(
            resource="https://mcp.example.com/mcp",
            resource_documentation="https://docs.example.com/mcp",
        ),
    )


def test_to_dict_includes_resource_documentation() -> None:
    endpoint = ProtectedResourceEndpoint(_config_with_resource_doc())
    metadata = endpoint.get_metadata()
    assert metadata["resource_documentation"] == "https://docs.example.com/mcp"


def test_public_base_url_is_used_for_auto_resource_metadata() -> None:
    config = MultiIdPConfig(
        idps=[IdPConfig(name="idp", issuer="https://issuer.example.com", audience="aud")],
        jwks_cache=JWKSCacheConfig(),
        security=SecurityConfig(),
        audit=AuditConfig(),
        role_mappings=[
            RoleMappingEntry(
                account_id="111111111111",
                role_arn="arn:aws:iam::111111111111:role/TestRole",
            )
        ],
        protected_resource=ProtectedResourceConfig(resource="auto"),
    )
    endpoint = ProtectedResourceEndpoint(
        config,
        public_base_url="https://mcp.public.example.com/base/",
    )
    metadata = endpoint.get_metadata()
    assert metadata["resource"] == "https://mcp.public.example.com/base/mcp"
