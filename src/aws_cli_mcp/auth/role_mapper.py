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

        # Validate all role ARNs are properly formatted
        for mapping in mappings:
            if not mapping.role_arn.startswith("arn:aws:iam::"):
                raise ValueError(f"Invalid role_arn format: {mapping.role_arn}")

        self._mappings = mappings
        logger.info("RoleMapper initialized with %d mappings", len(mappings))

    def resolve(self, context: RequestContext) -> ResolvedRole | None:
        """
        Resolve role for the given context.

        Returns the first matching role or None if no match.
        This is an allowlist-only resolver - no dynamic generation.
        """
        for mapping in self._mappings:
            if self._matches(mapping, context):
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

    def _matches(self, mapping: RoleMappingEntry, context: RequestContext) -> bool:
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
            if not context.email:
                return False
            email_domain = context.email.split("@")[-1].lower()
            if mapping.email_domain.lower() != email_domain:
                return False

        # groups match (any group matches, if specified)
        # groups is optional in both mapping and context
        if mapping.groups is not None:
            if not context.groups:
                return False
            mapping_groups = set(g.lower() for g in mapping.groups)
            context_groups = set(g.lower() for g in context.groups)
            if not mapping_groups & context_groups:
                return False

        # custom claims match (all must match, if specified)
        if mapping.claims is not None:
            for key, expected_value in mapping.claims.items():
                actual_value = context.raw_claims.get(key)
                if actual_value != expected_value:
                    return False

        return True

    def get_mappings_count(self) -> int:
        """Return number of configured mappings."""
        return len(self._mappings)
