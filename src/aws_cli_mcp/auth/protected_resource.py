"""OAuth 2.0 Protected Resource Metadata (RFC 9728) endpoint."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from aws_cli_mcp.utils.http import normalize_public_base_url, resolve_request_origin

from .idp_config import MultiIdPConfig


@dataclass
class ProtectedResourceMetadata:
    """OAuth 2.0 Protected Resource Metadata (RFC 9728)."""

    resource: str
    authorization_servers: list[str]
    scopes_supported: list[str]
    bearer_methods_supported: list[str]
    resource_documentation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict, omitting None values."""
        result: dict[str, Any] = {
            "resource": self.resource,
            "authorization_servers": self.authorization_servers,
            "scopes_supported": self.scopes_supported,
            "bearer_methods_supported": self.bearer_methods_supported,
        }
        if self.resource_documentation:
            result["resource_documentation"] = self.resource_documentation
        return result


class ProtectedResourceEndpoint:
    """Handler for /.well-known/oauth-protected-resource endpoint."""

    def __init__(
        self,
        config: MultiIdPConfig,
        trust_forwarded_headers: bool = False,
        public_base_url: str | None = None,
    ) -> None:
        self.config = config
        self._trust_forwarded_headers = trust_forwarded_headers
        self._public_base_url = (
            normalize_public_base_url(public_base_url) if public_base_url else None
        )
        self._metadata = self._build_metadata()

    @staticmethod
    def _is_gemini_cli_request(request: Request | None) -> bool:
        if request is None:
            return False
        user_agent = request.headers.get("user-agent", "")
        return "gemini" in user_agent.lower()

    @staticmethod
    def _normalize_nested_metadata_path(path: str) -> str:
        """Normalize duplicated well-known prefixes emitted by some clients."""
        duplicate = (
            "/.well-known/oauth-protected-resource/.well-known/oauth-protected-resource/"
        )
        if path.startswith(duplicate):
            suffix = path[len(duplicate) :]
            return f"/.well-known/oauth-protected-resource/{suffix}"
        return path

    def _origin(self, request: Request | None = None) -> str | None:
        if self._public_base_url:
            return self._public_base_url
        if request is None:
            return None
        return resolve_request_origin(
            request,
            trust_forwarded_headers=self._trust_forwarded_headers,
        )

    def _resolve_resource(self, request: Request | None = None) -> str:
        """
        Resolve protected resource identifier.

        If config value is "auto", derive canonical MCP resource URL from the incoming request.
        """
        configured = self.config.protected_resource.resource.strip()
        if configured.lower() != "auto":
            return configured

        origin = self._origin(request)
        if origin is None:
            return configured

        if self._is_gemini_cli_request(request) and request is not None:
            normalized_path = self._normalize_nested_metadata_path(request.url.path)
            if normalized_path.startswith("/.well-known/oauth-protected-resource/"):
                return f"{origin}{normalized_path}"

        return f"{origin}/mcp"

    def _resolve_authorization_servers(self, request: Request | None = None) -> list[str]:
        """
        Resolve authorization server URLs for PR metadata.

        In OAuth proxy mode, this server acts as the OAuth authorization server facade.
        """
        if not self.config.oauth_proxy.enabled:
            return self.config.get_authorization_servers()

        origin = self._origin(request)
        if origin is None:
            return self.config.get_authorization_servers()
        return [origin]

    def _build_metadata(self, request: Request | None = None) -> ProtectedResourceMetadata:
        """Build metadata from configuration."""
        pr_config = self.config.protected_resource
        resource = self._resolve_resource(request)
        scopes = [scope.replace("{resource}", resource) for scope in pr_config.scopes_supported]
        return ProtectedResourceMetadata(
            resource=resource,
            authorization_servers=self._resolve_authorization_servers(request),
            scopes_supported=scopes,
            bearer_methods_supported=list(pr_config.bearer_methods_supported),
            resource_documentation=pr_config.resource_documentation,
        )

    async def handle(self, request: Request) -> Response:
        """Handle GET /.well-known/oauth-protected-resource request."""
        metadata = self._build_metadata(request)
        return JSONResponse(
            content=metadata.to_dict(),
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "max-age=3600",  # Cache for 1 hour
            },
        )

    def get_metadata(self) -> dict[str, Any]:
        """Get metadata as dict (for testing/introspection)."""
        return self._metadata.to_dict()


def create_protected_resource_endpoint(
    config: MultiIdPConfig,
    trust_forwarded_headers: bool = False,
    public_base_url: str | None = None,
) -> ProtectedResourceEndpoint:
    """Factory function to create Protected Resource endpoint."""
    return ProtectedResourceEndpoint(
        config,
        trust_forwarded_headers=trust_forwarded_headers,
        public_base_url=public_base_url,
    )
