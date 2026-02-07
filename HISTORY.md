# AWS Tool-Execution MCP Server History

This file is the single source of truth for project versioning and change history.
`DESIGN.md` must not contain version history or changelog entries.

## [2.15] - 2026-02-07

### Security
- Hardened OAuth proxy authorization-code flow:
  - Enforced PKCE input validation and `S256` usage.
  - Enforced strict `client_id` + `redirect_uri` binding on `/token`.
  - Added redirect URI safety checks and loopback-only fallback for unregistered clients.
- Sanitized upstream token-exchange error responses to avoid leaking upstream internals to clients.
- Added in-memory store capacity guards for transactions/codes/registered-clients to reduce memory DoS risk.

### Tests
- Added/updated OAuth proxy tests for PKCE enforcement, redirect restrictions, required token parameters, and sanitized upstream error handling.

## [2.14] - 2026-02-07

### Changed
- Moved version/change-history management policy from `DESIGN.md` to `HISTORY.md`.
- Updated `DESIGN.md` meta section to reference this file as the history authority.

## [2.13] - 2026-02-07

### Changed
- Legacy config cleanup and redundancy reduction.
- Unified env parsing helpers and reduced duplicated boolean/integer parsing.
- Removed unused legacy security config key (`security.aws_timeout_seconds` / `AUTH_AWS_TIMEOUT_SECONDS`).
- Consolidated duplicated exempt-path and request-size response logic in HTTP middleware.

## [2.12] - 2026-02-07

### Changed
- Legacy module cleanup and readability pass.
- Removed old `oidc-sts` runtime branch remnants and aligned auth providers to:
  - `multi-idp`
  - `identity-center`

## Notes
- Older history entries can be backfilled later if needed.
