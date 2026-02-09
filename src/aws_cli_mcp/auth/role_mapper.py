"""Allowlist-based role mapper for AWS credentials."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .context import RequestContext
from .idp_config import RoleMappingEntry

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResolvedRole:
    """Resolved role information."""

    account_id: str
    role_arn: str
    mapping_entry: RoleMappingEntry


class RoleMapper:
    """
    Allowlist-based role mapper.

    Security principles:
    - Allowlist-only: Only explicitly configured mappings are allowed
    - No dynamic Role ARN generation
    - First-match-wins strategy
    - groups claim is optional (handles missing/huge groups)
    """

    def __init__(self, mappings: list[RoleMappingEntry]) -> None:
        if not mappings:
            raise ValueError("At least one role mapping must be configured")

        # Role ARN format is already validated in RoleMappingEntry.__post_init__.

        # Warn about catch-all mappings (no user/group/claim constraints).
        for i, mapping in enumerate(mappings):
            if (
                mapping.user_id is None
                and mapping.email is None
                and mapping.email_domain is None
                and mapping.groups is None
                and mapping.claims is None
            ):
                logger.warning(
                    "Role mapping #%d (%s) has no user/group/claim constraints — "
                    "it will match ALL authenticated users from any IdP.",
                    i,
                    mapping.role_arn,
                )

        self._mappings = mappings
        # Pre-compute lowered group sets for O(1) lookups.
        self._mapping_groups: list[frozenset[str] | None] = [
            frozenset(g.lower() for g in m.groups) if m.groups else None
            for m in mappings
        ]
        logger.info("RoleMapper initialized with %d mappings", len(mappings))

    def resolve(self, context: RequestContext) -> ResolvedRole | None:
        """
        Resolve role for the given context.

        Returns the first matching role or None if no match.
        This is an allowlist-only resolver - no dynamic generation.
        """
        # Pre-compute context groups once for all mappings.
        context_groups_lower: frozenset[str] | None = None
        if context.groups:
            context_groups_lower = frozenset(g.lower() for g in context.groups)

        for i, mapping in enumerate(self._mappings):
            if self._matches(mapping, context, self._mapping_groups[i], context_groups_lower):
                logger.debug(
                    "Role resolved for user %s: %s",
                    context.user_id,
                    mapping.role_arn,
                )
                return ResolvedRole(
                    account_id=mapping.account_id,
                    role_arn=mapping.role_arn,
                    mapping_entry=mapping,
                )

        logger.warning("No role mapping found for user %s", context.user_id)
        return None

    @staticmethod
    def _matches(
        mapping: RoleMappingEntry,
        context: RequestContext,
        mapping_groups_lower: frozenset[str] | None,
        context_groups_lower: frozenset[str] | None,
    ) -> bool:
        """Check if mapping matches context."""
        # user_id exact match (if specified)
        if mapping.user_id is not None:
            if mapping.user_id != context.user_id:
                return False

        # email exact match (case insensitive, if specified)
        if mapping.email is not None:
            if not context.email:
                return False
            if mapping.email.lower() != context.email.lower():
                return False

        # email_domain match (if specified)
        if mapping.email_domain is not None:
            if not context.email or "@" not in context.email:
                return False
            email_domain = context.email.rsplit("@", 1)[1].lower()
            if mapping.email_domain.lower() != email_domain:
                return False

        # groups match (any group matches, if specified)
        if mapping_groups_lower is not None:
            if not context_groups_lower:
                return False
            if not mapping_groups_lower & context_groups_lower:
                return False

        # custom claims match (all must match, if specified)
        if mapping.claims is not None:
            for key, expected_value in mapping.claims.items():
                actual_value = context.raw_claims.get(key)
                if str(actual_value) != expected_value:
                    return False

        return True

    def get_mappings_count(self) -> int:
        """Return number of configured mappings."""
        return len(self._mappings)
