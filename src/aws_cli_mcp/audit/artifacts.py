"""Artifact storage abstraction."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from aws_cli_mcp.audit.models import ArtifactRecord
from aws_cli_mcp.utils.hashing import sha256_bytes
from aws_cli_mcp.utils.serialization import json_default
from aws_cli_mcp.utils.time import utc_now_iso


class ArtifactStore:
    def __init__(self, base_path: str) -> None:
        self._base = Path(base_path)
        self._base.mkdir(parents=True, exist_ok=True)

    def write_json(self, kind: str, payload: dict, prefix: str | None = None) -> ArtifactRecord:
        data = json.dumps(payload, ensure_ascii=True, indent=2, default=json_default).encode(
            "utf-8"
        )
        return self._write_bytes(kind, data, suffix=".json", prefix=prefix)

    def read_json(self, location: str) -> dict:
        path = Path(location).resolve()
        # Validate that the resolved path is within the base directory
        # to prevent path traversal via tampered location values.
        if not path.is_relative_to(self._base.resolve()):
            raise ValueError(f"Path is outside base directory: {location}")
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def write_text(self, kind: str, text: str, prefix: str | None = None) -> ArtifactRecord:
        data = text.encode("utf-8")
        return self._write_bytes(kind, data, suffix=".txt", prefix=prefix)

    def _write_bytes(
        self, kind: str, data: bytes, suffix: str, prefix: str | None
    ) -> ArtifactRecord:
        artifact_id = uuid4().hex
        filename = f"{prefix + '-' if prefix else ''}{artifact_id}{suffix}"
        path = self._base / filename
        path.write_bytes(data)
        checksum = sha256_bytes(data)
        return ArtifactRecord(
            artifact_id=artifact_id,
            kind=kind,
            location=str(path),
            checksum=checksum,
            created_at=utc_now_iso(),
        )
