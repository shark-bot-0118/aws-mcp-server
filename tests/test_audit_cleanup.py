import pytest
import time
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from aws_cli_mcp.audit.db import SqliteStore
from aws_cli_mcp.audit.models import AuditTxRecord, AuditOpRecord, ArtifactRecord

@pytest.fixture
def store(tmp_path):
    db_path = tmp_path / "test.db"
    return SqliteStore(str(db_path))

def test_cleanup_pending_txs_removes_expired(store):
    # 1. Setup: Create expired pending tx
    expired_tx_id = "expired-token"
    # Create strictly expired time (2 hours ago)
    # We need to manually construct the ISO string since the store expects it on init?
    # Actually store methods take models, let's abuse that or inject manually.
    
    # Use direct SQL to inject specific timestamps to test expiration
    # Insert expired PendingConfirmation
    expired_start = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    store.create_tx(AuditTxRecord(
        tx_id=expired_tx_id,
        plan_id=None,
        status="PendingConfirmation",
        actor=None, role=None, account=None, region=None,
        started_at=expired_start,
        completed_at=None
    ))
    
    # 2. Setup: Create VALID pending tx (30 mins ago)
    valid_tx_id = "valid-token"
    valid_start = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    store.create_tx(AuditTxRecord(
        tx_id=valid_tx_id,
        plan_id=None,
        status="PendingConfirmation",
        actor=None, role=None, account=None, region=None,
        started_at=valid_start,
        completed_at=None
    ))

    # 3. Setup: Create EXPIRED but COMPLETED tx (should NOT be deleted)
    completed_tx_id = "completed-tx"
    store.create_tx(AuditTxRecord(
        tx_id=completed_tx_id,
        plan_id=None,
        status="Succeeded", # Not PendingConfirmation
        actor=None, role=None, account=None, region=None,
        started_at=expired_start,
        completed_at=None
    ))

    # 4. Insert related operations and artifacts for the expired pending tx
    store.create_op(AuditOpRecord(
        op_id="op-1", tx_id=expired_tx_id,
        service="s3", operation="DeleteObject", request_hash="abc",
        status="PendingConfirmation", duration_ms=None, error=None, response_summary=None,
        created_at=expired_start
    ))
    store.add_audit_artifact(ArtifactRecord(
        artifact_id="art-1", tx_id=expired_tx_id, op_id="op-1",
        kind="request", location="memory", checksum="123", created_at=expired_start
    ))

    # Run Cleanup (TTL = 3600 seconds = 1 hour)
    deleted_count = store.cleanup_pending_txs(3600)

    # Assertions
    assert deleted_count == 1
    
    # expired pending tx should be gone
    assert store.get_tx(expired_tx_id) is None
    
    # valid pending tx should remain
    assert store.get_tx(valid_tx_id) is not None
    
    # completed tx (even if old) should remain
    assert store.get_tx(completed_tx_id) is not None

    # Check cascade deletions for expired tx
    # Check op
    row = store._conn.execute("SELECT * FROM audit_op WHERE op_id='op-1'").fetchone()
    assert row is None
    
    # Check artifact
    row = store._conn.execute("SELECT * FROM audit_artifacts WHERE artifact_id='art-1'").fetchone()
    assert row is None
