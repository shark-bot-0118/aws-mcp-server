"""Shared HTTP utilities."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from starlette.requests import Request

_PUBLIC_BASE_URL_ALLOWED_SCHEMES = frozenset({"http", "https"})


def validate_oidc_url(url: str, *, label: str = "URL") -> str:
    """Validate that a URL discovered via OIDC is safe to fetch.

    Rejects non-HTTPS schemes and URLs that resolve to private/link-local
    IP ranges (SSRF protection).

    Returns the validated URL unchanged.

    Raises ``ValueError`` on validation failure.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"{label} must use HTTPS: {url}")
    if not parsed.hostname:
        raise ValueError(f"{label} has no hostname: {url}")

    # Resolve hostname and check for private/link-local addresses.
    hostname = parsed.hostname
    try:
        addr_infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        # DNS resolution failure — let the caller handle the connection error.
        return url

    for family, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError(
                f"{label} resolves to non-public address ({ip_str}): {url}"
            )

    return url


def first_forwarded_value(value: str | None) -> str | None:
    """Extract the first value from a comma-separated forwarded header.

    Used with X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Proto, etc.
    """
    if not value:
        return None
    first = value.split(",", 1)[0].strip()
    return first or None


def normalize_public_base_url(value: str) -> str:
    """Normalize and validate externally visible base URL for metadata/challenges."""
    candidate = value.strip()
    if not candidate:
        raise ValueError("public_base_url must not be empty")

    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in _PUBLIC_BASE_URL_ALLOWED_SCHEMES:
        raise ValueError("public_base_url must use http or https")
    if not parsed.netloc:
        raise ValueError("public_base_url must include host")
    if parsed.query or parsed.fragment:
        raise ValueError("public_base_url must not include query or fragment")
    if parsed.username or parsed.password:
        raise ValueError("public_base_url must not include userinfo")

    normalized_path = parsed.path.rstrip("/")
    if normalized_path == "/":
        normalized_path = ""
    return f"{parsed.scheme.lower()}://{parsed.netloc}{normalized_path}"


def resolve_request_origin(
    request: Request,
    *,
    trust_forwarded_headers: bool = False,
    public_base_url: str | None = None,
) -> str:
    """Resolve canonical origin for externally visible URLs."""
    if public_base_url:
        return normalize_public_base_url(public_base_url)

    forwarded_proto = None
    forwarded_host = None
    if trust_forwarded_headers:
        forwarded_proto = first_forwarded_value(request.headers.get("x-forwarded-proto"))
        forwarded_host = first_forwarded_value(request.headers.get("x-forwarded-host"))

    scheme = forwarded_proto or request.url.scheme
    host = forwarded_host or request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"
