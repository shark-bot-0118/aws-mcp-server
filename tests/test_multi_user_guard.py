from __future__ import annotations

import pytest

from aws_cli_mcp.auth import multi_user_guard
from aws_cli_mcp.auth.multi_user_guard import MultiUserViolationError, enforce_single_user_mode


@pytest.fixture(autouse=True)
def _reset_guard() -> None:
    multi_user_guard._guard._active_principal = None
    yield
    multi_user_guard._guard._active_principal = None


def test_enforce_single_user_mode_allows_first_principal() -> None:
    enforce_single_user_mode(user_id="u1", issuer="iss", allow_multi_user=False)


def test_enforce_single_user_mode_blocks_second_principal() -> None:
    enforce_single_user_mode(user_id="u1", issuer="iss", allow_multi_user=False)
    with pytest.raises(MultiUserViolationError):
        enforce_single_user_mode(user_id="u2", issuer="iss", allow_multi_user=False)


def test_enforce_single_user_mode_allows_multi_user_flag() -> None:
    enforce_single_user_mode(user_id="u1", issuer="iss", allow_multi_user=False)
    enforce_single_user_mode(user_id="u2", issuer="iss", allow_multi_user=True)
