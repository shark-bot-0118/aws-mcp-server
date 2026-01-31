import pytest
from aws_cli_mcp.audit.db import SqliteStore
from aws_cli_mcp.audit.models import AuditTxRecord, AuditOpRecord, ArtifactRecord

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "audit.db")

@pytest.fixture
def store(db_path):
    return SqliteStore(db_path)

def test_tx_lifecycle(store):
    rec = AuditTxRecord(
        tx_id="tx-1",
        plan_id=None,
        status="running",
        actor="user",
        role=None,
        account=None,
        region=None,
        started_at="now",
        completed_at=None
    )
    store.create_tx(rec)
    
    # Verify via direct SQL since there's no get_tx
    # Wait, store.get_tx exists in other tests? 
    # Let's trust the existing logic or check store method? 
    # Previous code used fetch_one.
    row = store.fetch_one("SELECT * FROM audit_tx WHERE tx_id=?", ("tx-1",))
    assert row["status"] == "running"
    
    store.update_tx_status("tx-1", "completed", "end-time")
    row = store.fetch_one("SELECT * FROM audit_tx WHERE tx_id=?", ("tx-1",))
    assert row["status"] == "completed"
    assert row["completed_at"] == "end-time"

def test_op_lifecycle(store):
    store.execute(
        "INSERT INTO audit_tx (tx_id, status, started_at) VALUES (?, ?, ?)",
        ("tx-1", "running", "now")
    )
    rec = AuditOpRecord(
        op_id="op-1",
        tx_id="tx-1",
        service="s3",
        operation="ListBuckets",
        request_hash="hash",
        status="running",
        duration_ms=None,
        error=None,
        response_summary=None,
        created_at="now"
    )
    store.create_op(rec)
    
    store.update_op_status("op-1", "success", 100, None, "{}")
    row = store.fetch_one("SELECT * FROM audit_op WHERE op_id=?", ("op-1",))
    assert row["status"] == "success"
    assert row["duration_ms"] == 100
    
def test_audit_artifact(store):
    # Create tx first for FK constraint
    tx = AuditTxRecord(
        tx_id="tx-1", plan_id=None, status="running", actor=None, role=None, account=None, region=None,
        started_at="now", completed_at=None
    )
    store.create_tx(tx)

    rec = ArtifactRecord(
        artifact_id="art-1",
        tx_id="tx-1",
        kind="json",
        location="/tmp/file",
        checksum="sha256:123",
        created_at="now"
    )
    store.add_audit_artifact(rec)
    
    row = store.fetch_one("SELECT * FROM audit_artifacts WHERE artifact_id=?", ("art-1",))
    assert row["location"] == "/tmp/file"

def test_wal_mode(tmp_path):
    # Verify WAL mode is set
    path = str(tmp_path / "wal.db")
    store = SqliteStore(path, wal=True)
    row = store.fetch_one("PRAGMA journal_mode", [])
    assert row[0].upper() == "WAL"
