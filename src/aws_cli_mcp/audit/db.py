"""SQLite access layer for audit logs, plans, and approvals."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

from aws_cli_mcp.utils.time import utc_now_iso

from aws_cli_mcp.audit.models import (
    ArtifactRecord,
    AuditOpRecord,
    AuditTxRecord,
)


class SqliteStore:
    def __init__(self, path: str, wal: bool = True) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if wal:
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS plans (
                plan_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                service TEXT NOT NULL,
                operation TEXT NOT NULL,
                account TEXT,
                region TEXT,
                role TEXT,
                params_redacted TEXT NOT NULL,
                context TEXT NOT NULL,
                validation_errors TEXT,
                policy_decision TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL,
                requester TEXT,
                approver TEXT,
                reason TEXT,
                status TEXT NOT NULL,
                expires_at TEXT,
                granted_at TEXT,
                FOREIGN KEY(plan_id) REFERENCES plans(plan_id)
            );

            CREATE TABLE IF NOT EXISTS audit_tx (
                tx_id TEXT PRIMARY KEY,
                plan_id TEXT,
                status TEXT NOT NULL,
                actor TEXT,
                role TEXT,
                account TEXT,
                region TEXT,
                approval_id TEXT,
                approval_actor TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY(plan_id) REFERENCES plans(plan_id),
                FOREIGN KEY(approval_id) REFERENCES approvals(approval_id)
            );

            CREATE TABLE IF NOT EXISTS audit_op (
                op_id TEXT PRIMARY KEY,
                tx_id TEXT NOT NULL,
                service TEXT NOT NULL,
                operation TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                duration_ms INTEGER,
                error TEXT,
                response_summary TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(tx_id) REFERENCES audit_tx(tx_id)
            );

            CREATE TABLE IF NOT EXISTS audit_artifacts (
                artifact_id TEXT PRIMARY KEY,
                tx_id TEXT,
                op_id TEXT,
                kind TEXT NOT NULL,
                location TEXT NOT NULL,
                checksum TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(tx_id) REFERENCES audit_tx(tx_id),
                FOREIGN KEY(op_id) REFERENCES audit_op(op_id)
            );

            CREATE TABLE IF NOT EXISTS plan_artifacts (
                artifact_id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                location TEXT NOT NULL,
                checksum TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(plan_id) REFERENCES plans(plan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_audit_tx_plan_id ON audit_tx(plan_id);
            CREATE INDEX IF NOT EXISTS idx_audit_op_tx_id ON audit_op(tx_id);
            CREATE INDEX IF NOT EXISTS idx_audit_op_request_hash ON audit_op(request_hash);
            CREATE INDEX IF NOT EXISTS idx_plan_status ON plans(status);
            CREATE INDEX IF NOT EXISTS idx_approval_plan_id ON approvals(plan_id);
            """
        )
        self._conn.commit()

    def execute(self, query: str, params: Iterable[object]) -> None:
        self._conn.execute(query, params)
        self._conn.commit()

    def fetch_one(self, query: str, params: Iterable[object]) -> sqlite3.Row | None:
        cur = self._conn.execute(query, params)
        return cur.fetchone()



    def create_tx(self, tx: AuditTxRecord) -> None:
        self.execute(
            """
            INSERT INTO audit_tx (
                tx_id, plan_id, status, actor, role, account, region,
                approval_id, approval_actor, started_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
            """,
            (
                tx.tx_id,
                tx.plan_id,
                tx.status,
                tx.actor,
                tx.role,
                tx.account,
                tx.region,
                tx.started_at,
                tx.completed_at,
            ),
        )

    def get_tx(self, tx_id: str) -> AuditTxRecord | None:
        row = self.fetch_one("SELECT * FROM audit_tx WHERE tx_id = ?", (tx_id,))
        if row is None:
            return None
        # Convert row to dict but filter out extra columns if any
        data = dict(row)
        # Remove approval columns from dict to match dataclass
        data.pop("approval_id", None)
        data.pop("approval_actor", None)
        return AuditTxRecord(**data)

    def update_tx_status(self, tx_id: str, status: str, completed_at: str | None) -> None:
        self.execute(
            "UPDATE audit_tx SET status = ?, completed_at = ? WHERE tx_id = ?",
            (status, completed_at, tx_id),
        )

    def create_op(self, op: AuditOpRecord) -> None:
        self.execute(
            """
            INSERT INTO audit_op (
                op_id, tx_id, service, operation, request_hash, status,
                duration_ms, error, response_summary, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                op.op_id,
                op.tx_id,
                op.service,
                op.operation,
                op.request_hash,
                op.status,
                op.duration_ms,
                op.error,
                op.response_summary,
                op.created_at,
            ),
        )

    def update_op_status(
        self,
        op_id: str,
        status: str,
        duration_ms: int | None,
        error: str | None,
        response_summary: str | None,
    ) -> None:
        self.execute(
            """
            UPDATE audit_op
            SET status = ?, duration_ms = ?, error = ?, response_summary = ?
            WHERE op_id = ?
            """,
            (status, duration_ms, error, response_summary, op_id),
        )

    def add_audit_artifact(self, artifact: ArtifactRecord) -> None:
        self.execute(
            """
            INSERT INTO audit_artifacts (
                artifact_id, tx_id, op_id, kind, location, checksum, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact.artifact_id,
                artifact.tx_id,
                artifact.op_id,
                artifact.kind,
                artifact.location,
                artifact.checksum,
                artifact.created_at,
            ),
        )



    def cleanup_pending_txs(self, ttl_seconds: int) -> int:
        """Delete pending transactions older than ttl_seconds.

        Returns:
            Number of transactions deleted.
        """
        import time

        # Calculate cutoff time
        cutoff_ms = (time.time() - ttl_seconds) * 1000
        # Convert to ISO format effectively?
        # Actually, stored dates are ISO strings. Comparing ISO strings works chronologically
        # mainly if they are UTC. our utc_now_iso returns UTC ISO.
        # But to be safe let's calculate the ISO string for the cutoff.
        from datetime import datetime, timedelta, timezone

        cutoff_dt = datetime.now(timezone.utc) - timedelta(seconds=ttl_seconds)
        cutoff_iso = cutoff_dt.isoformat().replace("+00:00", "Z")

        # Find expired tx_ids
        rows = self._conn.execute(
            "SELECT tx_id FROM audit_tx WHERE status = 'PendingConfirmation' AND started_at < ?",
            (cutoff_iso,),
        ).fetchall()

        if not rows:
            return 0

        expired_tx_ids = [row["tx_id"] for row in rows]
        
        # We need to delete associated operations and artifacts first if CASCADE is not on.
        # Since we use executemany or "IN" clause.
        placeholders = ",".join("?" for _ in expired_tx_ids)
        
        # 1. Delete associated artifacts (linked via tx_id)
        self._conn.execute(
            f"DELETE FROM audit_artifacts WHERE tx_id IN ({placeholders})",
            expired_tx_ids,
        )

        # 2. Delete associated operations
        self._conn.execute(
            f"DELETE FROM audit_op WHERE tx_id IN ({placeholders})",
            expired_tx_ids,
        )

        # 3. Delete the transactions
        cursor = self._conn.execute(
            f"DELETE FROM audit_tx WHERE tx_id IN ({placeholders})",
            expired_tx_ids,
        )
        self._conn.commit()

        return cursor.rowcount
