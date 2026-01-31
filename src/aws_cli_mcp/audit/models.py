"""Data models for audit and planning records."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AuditTxRecord:
    tx_id: str
    plan_id: str | None
    status: str
    actor: str | None
    role: str | None
    account: str | None
    region: str | None
    started_at: str
    completed_at: str | None


@dataclass
class AuditOpRecord:
    op_id: str
    tx_id: str
    service: str
    operation: str
    request_hash: str
    status: str
    duration_ms: int | None
    error: str | None
    response_summary: str | None
    created_at: str


@dataclass
class ArtifactRecord:
    artifact_id: str
    kind: str
    location: str
    checksum: str
    created_at: str
    tx_id: str | None = None
    op_id: str | None = None
    plan_id: str | None = None
    metadata: dict[str, object] | None = None
