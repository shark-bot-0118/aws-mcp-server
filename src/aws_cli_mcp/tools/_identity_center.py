"""Identity Center role selection and credential management."""

from __future__ import annotations

import asyncio
import re

from aws_cli_mcp.app import AppContext
from aws_cli_mcp.auth.context import (
    AWSCredentials,
    get_request_context_optional,
    update_request_context,
)
from aws_cli_mcp.aws_credentials.identity_center import (
    AccountEntry,
    IdentityCenterError,
    RoleEntry,
    get_identity_center_provider,
)
from aws_cli_mcp.mcp_runtime import ToolResult
from aws_cli_mcp.tools._helpers import _error_response
from aws_cli_mcp.tools.base import result_from_payload


def _identity_center_enabled(ctx: AppContext) -> bool:
    return ctx.settings.auth.provider.lower() == "identity-center"


def _parse_role_arn(role_arn: str) -> tuple[str, str] | None:
    match = re.match(r"^arn:aws(?:-cn|-us-gov)?:iam::(\d{12}):role/(.+)$", role_arn)
    if not match:
        return None
    return match.group(1), match.group(2)


def _role_selection_error(
    candidates: list[dict[str, object]],
) -> ToolResult:
    return result_from_payload(
        {
        "error": {
            "type": "RoleSelectionRequired",
            "message": (
                "Multiple roles available. "
                "Specify options.accountId and options.roleName."
            ),
            "candidates": candidates,
            "hint": (
                "Choose one of the listed roles and re-run the command with "
                    "options={'accountId': '...', 'roleName': '...'}."
                ),
                "retryable": True,
            },
        }
    )


def _identity_center_error(
    message: str,
) -> ToolResult:
    return _error_response(
        "IdentityCenterError",
        message,
        hint="Re-authenticate with IAM Identity Center and try again.",
        retryable=True,
    )


async def _resolve_identity_center_role_selection(
    ctx: AppContext,
    options: dict[str, object],
) -> tuple[str, str] | ToolResult:
    request_ctx = get_request_context_optional()
    if request_ctx is None or not request_ctx.access_token:
        return _error_response(
            "IdentityCenterAuthMissing",
            "Missing Identity Center access token.",
            hint="Provide an SSO access token via Authorization: Bearer <token>.",
        )
    access_token = request_ctx.access_token

    account_id: str | None = None
    role_name: str | None = None
    role_arn: str | None = None
    raw_account_id = options.get("accountId")
    raw_role_name = options.get("roleName")
    raw_role_arn = options.get("roleArn")
    if isinstance(raw_account_id, str) and raw_account_id.strip():
        account_id = raw_account_id
    if isinstance(raw_role_name, str) and raw_role_name.strip():
        role_name = raw_role_name
    if isinstance(raw_role_arn, str) and raw_role_arn.strip():
        role_arn = raw_role_arn

    if role_arn and not (account_id or role_name):
        parsed = _parse_role_arn(role_arn)
        if parsed:
            account_id, role_name = parsed

    if (account_id and not role_name) or (role_name and not account_id):
        return _error_response(
            "RoleSelectionInvalid",
            "Both options.accountId and options.roleName are required.",
            hint="Provide both accountId and roleName (or a roleArn).",
        )

    provider = get_identity_center_provider()

    if account_id and role_name:
        try:
            roles = await provider.list_account_roles(access_token, account_id)
        except IdentityCenterError as exc:
            return _identity_center_error(str(exc))
        if not any(role.role_name == role_name for role in roles):
            return _error_response(
                "RoleNotAssigned",
                "The specified role is not assigned to this user.",
                hint="Select a role from the available candidates.",
            )
        return account_id, role_name

    try:
        accounts = await provider.list_accounts(access_token)
    except IdentityCenterError as exc:
        return _identity_center_error(str(exc))

    # Fetch roles for all accounts in parallel with concurrency limit
    _semaphore = asyncio.Semaphore(10)

    async def fetch_roles_for_account(
        account: AccountEntry,
    ) -> tuple[AccountEntry, list[RoleEntry]]:
        async with _semaphore:
            roles = await provider.list_account_roles(access_token, account.account_id)
            return account, roles

    try:
        results = await asyncio.gather(
            *(fetch_roles_for_account(account) for account in accounts),
            return_exceptions=True,
        )
    except Exception as exc:
        return _identity_center_error(str(exc))

    candidates: list[dict[str, object]] = []
    for result in results:
        if isinstance(result, Exception):
            return _identity_center_error(
                f"Unexpected error fetching roles: {result}",
            )
        if (
            not isinstance(result, tuple)
            or len(result) != 2
            or not isinstance(result[1], list)
        ):
            return _identity_center_error(
                "Unexpected role selection result type",
            )
        account, roles = result
        account_name = getattr(account, "account_name", None)
        for role in roles:
            account_id = getattr(role, "account_id", None)
            role_name = getattr(role, "role_name", None)
            if not isinstance(account_id, str) or not isinstance(role_name, str):
                continue
            candidates.append(
                {
                    "accountId": account_id,
                    "accountName": account_name if isinstance(account_name, str) else None,
                    "roleName": role_name,
                }
            )

    if not candidates:
        return _error_response(
            "NoRolesAvailable",
            "No roles are available for this Identity Center user.",
            hint="Verify role assignments in IAM Identity Center.",
        )

    if len(candidates) == 1:
        only = candidates[0]
        return str(only["accountId"]), str(only["roleName"])

    return _role_selection_error(candidates)


async def _ensure_identity_center_credentials(
    ctx: AppContext,
    account_id: str,
    role_name: str,
) -> ToolResult | None:
    request_ctx = get_request_context_optional()
    if request_ctx is None or not request_ctx.access_token:
        return _error_response(
            "IdentityCenterAuthMissing",
            "Missing Identity Center access token.",
            hint="Provide an SSO access token via Authorization: Bearer <token>.",
        )

    provider = get_identity_center_provider()
    try:
        temp_creds = await provider.get_cached_role_credentials(
            request_ctx.access_token,
            account_id,
            role_name,
            request_ctx.user_id,
        )
    except IdentityCenterError as exc:
        return _identity_center_error(str(exc))

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    aws_creds = AWSCredentials(
        access_key_id=temp_creds.access_key_id,
        secret_access_key=temp_creds.secret_access_key,
        session_token=temp_creds.session_token,
        expiration=temp_creds.expiration,
    )
    update_request_context(lambda c: c.with_aws_credentials(aws_creds, account_id, role_arn))
    return None
