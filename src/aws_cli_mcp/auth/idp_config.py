"""IdP configuration loader for multi-IdP OAuth 2.0 authentication."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


@dataclass(frozen=True)
class IdPConfig:
    """Configuration for a single Identity Provider."""

    name: str
    issuer: str
    audience: str | list[str]
    jwks_uri: str | None = None
    allowed_algorithms: tuple[str, ...] = ("RS256", "ES256")
    clock_skew_seconds: int = 30
    claims_mapping: dict[str, str] = field(
        default_factory=lambda: {
            "user_id": "sub",
            "email": "email",
            "groups": "groups",
        }
    )

    def get_audience_set(self) -> set[str]:
        """Return audience as a set for validation."""
        if isinstance(self.audience, str):
            return {self.audience}
        return set(self.audience)

    def get_normalized_issuer(self) -> str:
        """Return issuer with trailing slash removed."""
        return self.issuer.rstrip("/")


@dataclass(frozen=True)
class JWKSCacheConfig:
    """JWKS cache configuration."""

    ttl_seconds: int = 3600
    refresh_before_seconds: int = 300
    failure_backoff_seconds: int = 60
    max_retries: int = 3


@dataclass(frozen=True)
class SecurityConfig:
    """Security middleware configuration."""

    rate_limit_per_user: int = 100  # requests per minute
    rate_limit_per_ip: int = 1000  # requests per minute
    max_body_size_bytes: int = 10 * 1024 * 1024  # 10MB
    max_header_size_bytes: int = 8 * 1024  # 8KB
    request_timeout_seconds: float = 30.0


@dataclass(frozen=True)
class AuditConfig:
    """Audit logging configuration."""

    enabled: bool = True
    mask_fields: tuple[str, ...] = (
        "access_token",
        "refresh_token",
        "id_token",
        "secret",
        "password",
        "credential",
        "authorization",
        "secret_access_key",
        "session_token",
    )


@dataclass(frozen=True)
class RoleMappingEntry:
    """Role mapping entry for allowlist-based role resolution."""

    account_id: str
    role_arn: str
    user_id: str | None = None
    email: str | None = None
    email_domain: str | None = None
    groups: tuple[str, ...] | None = None
    claims: dict[str, str] | None = None

    # Full ARN pattern: arn:aws(-cn|-us-gov)?:iam::<12-digit>:role/<path>
    _ROLE_ARN_RE = re.compile(
        r"^arn:aws(?:-cn|-us-gov)?:iam::\d{12}:role/[\w+=,.@/-]+$"
    )

    def __post_init__(self) -> None:
        """Validate role_arn format."""
        if not self._ROLE_ARN_RE.match(self.role_arn):
            raise ValueError(f"Invalid role_arn format: {self.role_arn}")
        if not self.account_id or not self.account_id.isdigit() or len(self.account_id) != 12:
            raise ValueError(f"Invalid account_id: {self.account_id}")


@dataclass(frozen=True)
class ProtectedResourceConfig:
    """OAuth 2.0 Protected Resource metadata configuration."""

    resource: str
    scopes_supported: tuple[str, ...] = ("openid", "profile", "offline_access")
    bearer_methods_supported: tuple[str, ...] = ("header",)
    resource_documentation: str | None = None


@dataclass(frozen=True)
class OAuthProxyConfig:
    """OAuth broker/proxy configuration."""

    enabled: bool = False
    upstream_idp: str | None = None
    upstream_client_id: str | None = None
    upstream_client_secret: str | None = None
    upstream_token_auth_method: str = "auto"
    upstream_scopes: tuple[str, ...] = ("openid", "profile", "offline_access")
    redirect_path: str = "/oauth/callback"
    auth_code_ttl_seconds: int = 300
    transaction_ttl_seconds: int = 300


@dataclass
class MultiIdPConfig:
    """Complete multi-IdP configuration."""

    idps: list[IdPConfig]
    jwks_cache: JWKSCacheConfig
    security: SecurityConfig
    audit: AuditConfig
    role_mappings: list[RoleMappingEntry]
    protected_resource: ProtectedResourceConfig
    oauth_proxy: OAuthProxyConfig = field(default_factory=OAuthProxyConfig)

    def get_authorization_servers(self) -> list[str]:
        """Return list of IdP issuers for protected resource metadata."""
        return [idp.get_normalized_issuer() for idp in self.idps]

    def get_idp_by_issuer(self, issuer: str) -> IdPConfig | None:
        """Find IdP config by normalized issuer."""
        normalized = issuer.rstrip("/")
        for idp in self.idps:
            if idp.get_normalized_issuer() == normalized:
                return idp
        return None

    def get_idp_by_name(self, name: str) -> IdPConfig | None:
        """Find IdP config by name."""
        for idp in self.idps:
            if idp.name == name:
                return idp
        return None


def _substitute_env_vars(value: str) -> str:
    """Substitute ${VAR} and $VAR patterns with environment variables."""

    def replace(match: re.Match[str]) -> str:
        var_name = match.group(1) or match.group(2)
        return os.environ.get(var_name, match.group(0))

    # Match ${VAR} or $VAR patterns. Variable names restricted to safe identifiers.
    pattern = r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)"
    return re.sub(pattern, replace, value)


_MAX_ENV_VAR_DEPTH = 20


def _process_env_vars(obj: Any, _depth: int = 0) -> Any:
    """Recursively substitute environment variables in strings."""
    if _depth > _MAX_ENV_VAR_DEPTH:
        return obj
    if isinstance(obj, str):
        return _substitute_env_vars(obj)
    elif isinstance(obj, dict):
        return {k: _process_env_vars(v, _depth + 1) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_process_env_vars(item, _depth + 1) for item in obj]
    return obj


def _project_root() -> Path:
    """Resolve project root by locating pyproject.toml."""
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "pyproject.toml").exists():
            return parent
    # Fallback: repo layout is /<root>/src/aws_cli_mcp/auth/idp_config.py
    return current.parents[3]


def _parse_idp_config(data: dict[str, Any]) -> IdPConfig:
    """Parse a single IdP configuration from dict."""
    audience = data.get("audience", "")
    if isinstance(audience, list):
        audience = list(audience)

    algorithms = data.get("allowed_algorithms", ["RS256", "ES256"])
    if isinstance(algorithms, str):
        algorithms = [a.strip() for a in algorithms.split(",")]

    claims_mapping = data.get("claims_mapping", {})

    return IdPConfig(
        name=data["name"],
        issuer=data["issuer"],
        audience=audience,
        jwks_uri=data.get("jwks_uri"),
        allowed_algorithms=tuple(algorithms),
        clock_skew_seconds=int(data.get("clock_skew_seconds", 30)),
        claims_mapping=claims_mapping,
    )


def _parse_role_mapping(data: dict[str, Any]) -> RoleMappingEntry:
    """Parse a single role mapping entry from dict."""
    groups = data.get("groups")
    if groups is not None:
        groups = tuple(groups) if isinstance(groups, list) else (groups,)

    claims = data.get("claims")
    if claims is not None and not isinstance(claims, dict):
        raise ValueError(f"claims must be a dict, got {type(claims)}")

    return RoleMappingEntry(
        account_id=str(data["account_id"]),
        role_arn=data["role_arn"],
        user_id=data.get("user_id"),
        email=data.get("email"),
        email_domain=data.get("email_domain"),
        groups=groups,
        claims=claims,
    )


def _normalize_scope_list(raw_scopes: Any, field_name: str) -> tuple[str, ...]:
    """Normalize and validate scope list."""
    if not isinstance(raw_scopes, list):
        raise ValueError(f"{field_name} must be a list of strings")

    normalized: list[str] = []
    for raw_scope in raw_scopes:
        if not isinstance(raw_scope, str):
            raise ValueError(f"{field_name} must contain only strings")
        scope = raw_scope.strip()
        if not scope:
            raise ValueError(f"{field_name} contains an empty scope")
        normalized.append(scope)
    return tuple(normalized)


def _parse_oauth_proxy_config(data: dict[str, Any], idps: list[IdPConfig]) -> OAuthProxyConfig:
    """Parse OAuth proxy configuration from dict."""
    proxy_data = data.get("oauth_proxy", {})
    enabled = bool(proxy_data.get("enabled", False))
    upstream_idp = proxy_data.get("upstream_idp")
    upstream_client_secret_raw = proxy_data.get("upstream_client_secret")
    upstream_client_secret = (
        str(upstream_client_secret_raw).strip() if upstream_client_secret_raw is not None else None
    )
    if upstream_client_secret == "":
        upstream_client_secret = None
    upstream_token_auth_method = str(proxy_data.get("upstream_token_auth_method", "auto")).strip()
    upstream_token_auth_method = upstream_token_auth_method.lower() or "auto"
    upstream_scopes = _normalize_scope_list(
        proxy_data.get("upstream_scopes", ["openid", "profile", "offline_access"]),
        "oauth_proxy.upstream_scopes",
    )
    redirect_path = str(proxy_data.get("redirect_path", "/oauth/callback")).strip()
    if not redirect_path.startswith("/"):
        raise ValueError("oauth_proxy.redirect_path must start with '/'")

    config = OAuthProxyConfig(
        enabled=enabled,
        upstream_idp=upstream_idp,
        upstream_client_id=proxy_data.get("upstream_client_id"),
        upstream_client_secret=upstream_client_secret,
        upstream_token_auth_method=upstream_token_auth_method,
        upstream_scopes=upstream_scopes,
        redirect_path=redirect_path,
        auth_code_ttl_seconds=int(proxy_data.get("auth_code_ttl_seconds", 300)),
        transaction_ttl_seconds=int(proxy_data.get("transaction_ttl_seconds", 300)),
    )

    if not enabled:
        return config

    valid_auth_methods = {"auto", "client_secret_post", "none"}
    if config.upstream_token_auth_method not in valid_auth_methods:
        raise ValueError(
            "oauth_proxy.upstream_token_auth_method must be one of "
            "'auto', 'client_secret_post', 'none'"
        )
    if not config.upstream_client_id:
        raise ValueError("oauth_proxy.upstream_client_id is required when oauth_proxy.enabled=true")
    if (
        config.upstream_token_auth_method == "client_secret_post"
        and not config.upstream_client_secret
    ):
        raise ValueError(
            "oauth_proxy.upstream_client_secret is required when "
            "oauth_proxy.upstream_token_auth_method=client_secret_post"
        )
    if config.auth_code_ttl_seconds <= 0:
        raise ValueError("oauth_proxy.auth_code_ttl_seconds must be positive")
    if config.transaction_ttl_seconds <= 0:
        raise ValueError("oauth_proxy.transaction_ttl_seconds must be positive")

    if config.upstream_idp:
        idp_names = {idp.name for idp in idps}
        if config.upstream_idp not in idp_names:
            raise ValueError(
                f"oauth_proxy.upstream_idp '{config.upstream_idp}' not found in configured idps"
            )

    return config


def load_idp_config(config_path: str | Path) -> MultiIdPConfig:
    """Load multi-IdP configuration from YAML file."""
    load_dotenv(dotenv_path=_project_root() / ".env")
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"IdP config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw_data = yaml.safe_load(f)

    # Substitute environment variables
    data = _process_env_vars(raw_data)

    # Parse IdPs
    idps_data = data.get("idps", [])
    if not idps_data:
        raise ValueError("At least one IdP must be configured")
    idps = [_parse_idp_config(idp) for idp in idps_data]

    # Parse JWKS cache config
    jwks_data = data.get("jwks_cache", {})
    jwks_cache = JWKSCacheConfig(
        ttl_seconds=int(jwks_data.get("ttl_seconds", 3600)),
        refresh_before_seconds=int(jwks_data.get("refresh_before_seconds", 300)),
        failure_backoff_seconds=int(jwks_data.get("failure_backoff_seconds", 60)),
        max_retries=int(jwks_data.get("max_retries", 3)),
    )

    # Parse security config
    sec_data = data.get("security", {})
    security = SecurityConfig(
        rate_limit_per_user=int(sec_data.get("rate_limit_per_user", 100)),
        rate_limit_per_ip=int(sec_data.get("rate_limit_per_ip", 1000)),
        max_body_size_bytes=int(sec_data.get("max_body_size_mb", 10)) * 1024 * 1024,
        max_header_size_bytes=int(sec_data.get("max_header_size_kb", 8)) * 1024,
        request_timeout_seconds=float(sec_data.get("request_timeout_seconds", 30.0)),
    )

    # Parse audit config
    audit_data = data.get("audit", {})
    mask_fields = audit_data.get("mask_fields", list(AuditConfig.mask_fields))
    audit = AuditConfig(
        enabled=audit_data.get("enabled", True),
        mask_fields=tuple(mask_fields),
    )

    # Parse role mappings
    mappings_data = data.get("role_mappings", [])
    if not mappings_data:
        raise ValueError("At least one role mapping must be configured")
    role_mappings = [_parse_role_mapping(m) for m in mappings_data]

    # Parse protected resource config
    pr_data = data.get("protected_resource", {})
    resource_url = pr_data.get("resource", "")
    if not resource_url:
        raise ValueError("protected_resource.resource URL is required")
    if not isinstance(resource_url, str):
        raise ValueError(
            "protected_resource.resource must be a string. "
            "Use a single URL string or 'auto' for runtime resolution."
        )
    resource_url = resource_url.strip()
    if not resource_url:
        raise ValueError("protected_resource.resource URL is required")

    normalized_scopes = _normalize_scope_list(
        pr_data.get("scopes_supported", ["openid", "profile", "offline_access"]),
        "protected_resource.scopes_supported",
    )

    protected_resource = ProtectedResourceConfig(
        resource=resource_url,
        scopes_supported=normalized_scopes,
        bearer_methods_supported=tuple(pr_data.get("bearer_methods_supported", ["header"])),
        resource_documentation=pr_data.get("resource_documentation"),
    )
    oauth_proxy = _parse_oauth_proxy_config(data, idps)

    return MultiIdPConfig(
        idps=idps,
        jwks_cache=jwks_cache,
        security=security,
        audit=audit,
        role_mappings=role_mappings,
        protected_resource=protected_resource,
        oauth_proxy=oauth_proxy,
    )
