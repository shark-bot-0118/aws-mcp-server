"""Domain objects for AWS operations."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OperationRef:
    service: str
    operation: str

    @property
    def key(self) -> str:
        return f"{self.service}:{self.operation}"
