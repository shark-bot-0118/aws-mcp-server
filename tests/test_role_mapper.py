"""Tests for RoleMapper."""

from __future__ import annotations

import pytest

from aws_cli_mcp.auth.context import RequestContext
from aws_cli_mcp.auth.idp_config import RoleMappingEntry
from aws_cli_mcp.auth.role_mapper import RoleMapper


def _create_context(
    user_id: str = "test-user",
    email: str | None = "user@example.com",
    groups: tuple[str, ...] | None = ("developers",),
    issuer: str = "https://test.example.com",
    raw_claims: dict | None = None,
) -> RequestContext:
    """Create a test RequestContext."""
    return RequestContext(
        user_id=user_id,
        email=email,
        groups=groups,
        issuer=issuer,
        raw_claims=raw_claims or {},
    )


class TestRoleMapperInitialization:
    """Tests for RoleMapper initialization."""

    def test_requires_at_least_one_mapping(self) -> None:
        """RoleMapper should require at least one mapping."""
        with pytest.raises(ValueError, match="(?i)at least one"):
            RoleMapper([])

    def test_validates_role_arn_format(self) -> None:
        """RoleMapper should validate role ARN format."""
        invalid_mapping = object.__new__(RoleMappingEntry)
        object.__setattr__(invalid_mapping, "account_id", "111111111111")
        object.__setattr__(invalid_mapping, "role_arn", "invalid-arn")
        object.__setattr__(invalid_mapping, "user_id", None)
        object.__setattr__(invalid_mapping, "email", None)
        object.__setattr__(invalid_mapping, "email_domain", None)
        object.__setattr__(invalid_mapping, "groups", None)
        object.__setattr__(invalid_mapping, "claims", None)

        with pytest.raises(ValueError, match="Invalid role_arn"):
            RoleMapper([invalid_mapping])

    def test_valid_initialization(self) -> None:
        """RoleMapper should initialize with valid mappings."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/TestRole",
                ),
            ]
        )
        assert mapper.get_mappings_count() == 1


class TestUserIdMatching:
    """Tests for user_id matching."""

    def test_user_id_exact_match(self) -> None:
        """Exact user_id match should work."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    user_id="specific-user",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/SpecificRole",
                ),
            ]
        )

        context = _create_context(user_id="specific-user")
        resolved = mapper.resolve(context)

        assert resolved is not None
        assert resolved.role_arn == "arn:aws:iam::111111111111:role/SpecificRole"

    def test_user_id_no_match(self) -> None:
        """Non-matching user_id should not match."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    user_id="other-user",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/OtherRole",
                ),
            ]
        )

        context = _create_context(user_id="test-user")
        resolved = mapper.resolve(context)

        assert resolved is None


class TestEmailMatching:
    """Tests for email matching."""

    def test_email_exact_match(self) -> None:
        """Exact email match should work."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    email="admin@example.com",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/AdminRole",
                ),
            ]
        )

        context = _create_context(email="admin@example.com")
        resolved = mapper.resolve(context)

        assert resolved is not None
        assert resolved.role_arn == "arn:aws:iam::111111111111:role/AdminRole"

    def test_email_case_insensitive(self) -> None:
        """Email matching should be case insensitive."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    email="Admin@Example.COM",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/AdminRole",
                ),
            ]
        )

        context = _create_context(email="admin@example.com")
        resolved = mapper.resolve(context)

        assert resolved is not None

    def test_email_no_match_when_none(self) -> None:
        """Email mapping should not match when context email is None."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    email="user@example.com",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/TestRole",
                ),
            ]
        )

        context = _create_context(email=None)
        resolved = mapper.resolve(context)

        assert resolved is None

    def test_email_no_match_when_different(self) -> None:
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    email="admin@example.com",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/AdminRole",
                ),
            ]
        )

        context = _create_context(email="user@example.com")
        assert mapper.resolve(context) is None


class TestEmailDomainMatching:
    """Tests for email_domain matching."""

    def test_email_domain_match(self) -> None:
        """Email domain matching should work."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    email_domain="example.com",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/DomainRole",
                ),
            ]
        )

        context = _create_context(email="anyone@example.com")
        resolved = mapper.resolve(context)

        assert resolved is not None
        assert resolved.role_arn == "arn:aws:iam::111111111111:role/DomainRole"

    def test_email_domain_case_insensitive(self) -> None:
        """Email domain matching should be case insensitive."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    email_domain="EXAMPLE.COM",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/DomainRole",
                ),
            ]
        )

        context = _create_context(email="user@example.com")
        resolved = mapper.resolve(context)

        assert resolved is not None

    def test_email_domain_no_match(self) -> None:
        """Non-matching domain should not match."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    email_domain="company.com",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/CompanyRole",
                ),
            ]
        )

        context = _create_context(email="user@example.com")
        resolved = mapper.resolve(context)

        assert resolved is None

    def test_email_domain_no_match_when_email_missing(self) -> None:
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    email_domain="company.com",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/CompanyRole",
                ),
            ]
        )

        context = _create_context(email=None)
        assert mapper.resolve(context) is None


class TestGroupsMatching:
    """Tests for groups matching."""

    def test_groups_any_match(self) -> None:
        """Any matching group should satisfy the condition."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    groups=("admins", "superusers"),
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/AdminRole",
                ),
            ]
        )

        context = _create_context(groups=("developers", "admins"))
        resolved = mapper.resolve(context)

        assert resolved is not None

    def test_groups_case_insensitive(self) -> None:
        """Groups matching should be case insensitive."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    groups=("ADMINS",),
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/AdminRole",
                ),
            ]
        )

        context = _create_context(groups=("admins",))
        resolved = mapper.resolve(context)

        assert resolved is not None

    def test_groups_no_match_when_none(self) -> None:
        """Groups mapping should not match when context groups is None."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    groups=("admins",),
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/AdminRole",
                ),
            ]
        )

        context = _create_context(groups=None)
        resolved = mapper.resolve(context)

        assert resolved is None

    def test_groups_optional_when_not_specified(self) -> None:
        """Mapping without groups should not require context groups."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    email_domain="example.com",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/DomainRole",
                ),
            ]
        )

        context = _create_context(groups=None, email="user@example.com")
        resolved = mapper.resolve(context)

        assert resolved is not None

    def test_groups_no_overlap(self) -> None:
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    groups=("admins",),
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/AdminRole",
                ),
            ]
        )

        context = _create_context(groups=("developers",))
        assert mapper.resolve(context) is None


class TestCustomClaimsMatching:
    """Tests for custom claims matching."""

    def test_custom_claims_all_match(self) -> None:
        """All custom claims must match."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    claims={"department": "engineering", "level": "senior"},
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/EngineerRole",
                ),
            ]
        )

        context = _create_context(
            raw_claims={"department": "engineering", "level": "senior", "other": "value"}
        )
        resolved = mapper.resolve(context)

        assert resolved is not None

    def test_custom_claims_partial_match_fails(self) -> None:
        """Partial custom claims match should fail."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    claims={"department": "engineering", "level": "senior"},
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/EngineerRole",
                ),
            ]
        )

        context = _create_context(raw_claims={"department": "engineering"})
        resolved = mapper.resolve(context)

        assert resolved is None

    def test_custom_claims_value_mismatch(self) -> None:
        """Custom claims with wrong value should fail."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    claims={"department": "engineering"},
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/EngineerRole",
                ),
            ]
        )

        context = _create_context(raw_claims={"department": "marketing"})
        resolved = mapper.resolve(context)

        assert resolved is None


class TestFirstMatchWins:
    """Tests for first-match-wins behavior."""

    def test_first_match_returned(self) -> None:
        """First matching mapping should be returned."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    email_domain="example.com",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/FirstRole",
                ),
                RoleMappingEntry(
                    email_domain="example.com",
                    account_id="222222222222",
                    role_arn="arn:aws:iam::222222222222:role/SecondRole",
                ),
            ]
        )

        context = _create_context(email="user@example.com")
        resolved = mapper.resolve(context)

        assert resolved is not None
        assert resolved.role_arn == "arn:aws:iam::111111111111:role/FirstRole"

    def test_more_specific_first(self) -> None:
        """More specific mapping should be placed first for priority."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    user_id="special-user",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/SpecialRole",
                ),
                RoleMappingEntry(
                    email_domain="example.com",
                    account_id="222222222222",
                    role_arn="arn:aws:iam::222222222222:role/DomainRole",
                ),
            ]
        )

        # Special user should match first rule
        context = _create_context(user_id="special-user", email="special-user@example.com")
        resolved = mapper.resolve(context)

        assert resolved is not None
        assert resolved.role_arn == "arn:aws:iam::111111111111:role/SpecialRole"

        # Normal user should match second rule
        context = _create_context(user_id="normal-user", email="normal@example.com")
        resolved = mapper.resolve(context)

        assert resolved is not None
        assert resolved.role_arn == "arn:aws:iam::222222222222:role/DomainRole"


class TestNoMatchReturnsNone:
    """Tests for no-match behavior."""

    def test_no_match_returns_none(self) -> None:
        """No matching mapping should return None."""
        mapper = RoleMapper(
            [
                RoleMappingEntry(
                    email_domain="company.com",
                    account_id="111111111111",
                    role_arn="arn:aws:iam::111111111111:role/CompanyRole",
                ),
            ]
        )

        context = _create_context(email="user@other.com")
        resolved = mapper.resolve(context)

        assert resolved is None


class TestResolvedRole:
    """Tests for ResolvedRole dataclass."""

    def test_resolved_role_contains_mapping_entry(self) -> None:
        """ResolvedRole should contain the original mapping entry."""
        mapping = RoleMappingEntry(
            email_domain="example.com",
            account_id="111111111111",
            role_arn="arn:aws:iam::111111111111:role/TestRole",
        )
        mapper = RoleMapper([mapping])

        context = _create_context(email="user@example.com")
        resolved = mapper.resolve(context)

        assert resolved is not None
        assert resolved.mapping_entry == mapping
        assert resolved.account_id == "111111111111"
        assert resolved.role_arn == "arn:aws:iam::111111111111:role/TestRole"


class TestRoleMappingEntryValidation:
    """Tests for RoleMappingEntry validation."""

    def test_invalid_account_id(self) -> None:
        """Invalid account_id should raise error."""
        with pytest.raises(ValueError, match="account_id"):
            RoleMappingEntry(
                account_id="invalid",
                role_arn="arn:aws:iam::111111111111:role/TestRole",
            )

    def test_account_id_wrong_length(self) -> None:
        """Account ID with wrong length should raise error."""
        with pytest.raises(ValueError, match="account_id"):
            RoleMappingEntry(
                account_id="12345",  # Too short
                role_arn="arn:aws:iam::111111111111:role/TestRole",
            )

    def test_invalid_role_arn(self) -> None:
        """Invalid role ARN should raise error."""
        with pytest.raises(ValueError, match="role_arn"):
            RoleMappingEntry(
                account_id="111111111111",
                role_arn="not-an-arn",
            )
