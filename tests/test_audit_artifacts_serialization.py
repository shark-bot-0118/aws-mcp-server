from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from aws_cli_mcp.audit.artifacts import ArtifactStore


def test_artifact_store_write_and_read_json(tmp_path: Path) -> None:
    store = ArtifactStore(str(tmp_path))
    payload = {
        "timestamp": datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "binary": b"bytes-data",
    }

    record = store.write_json("request", payload, prefix="tx")
    loaded = store.read_json(record.location)

    assert record.kind == "request"
    assert Path(record.location).exists()
    assert isinstance(loaded["timestamp"], str)
    assert isinstance(loaded["binary"], str)


def test_artifact_store_write_text(tmp_path: Path) -> None:
    store = ArtifactStore(str(tmp_path))
    record = store.write_text("summary", "hello", prefix="op")

    assert record.kind == "summary"
    assert Path(record.location).suffix == ".txt"
    assert Path(record.location).read_text(encoding="utf-8") == "hello"


def test_artifact_store_read_json_rejects_path_outside_base(tmp_path: Path) -> None:
    store = ArtifactStore(str(tmp_path))
    outside = tmp_path.parent / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="outside base directory"):
        store.read_json(str(outside))
