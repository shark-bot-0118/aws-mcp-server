"""Smithy model registry and routing helpers."""

from __future__ import annotations

from pathlib import Path


def resolve_service_model_paths(base_path: str, services: list[str]) -> dict[str, Path]:
    root = Path(base_path)
    models_dir = root / "models" if (root / "models").exists() else root
    if not models_dir.exists():
        raise FileNotFoundError(f"Smithy models directory not found: {models_dir}")

    resolved: dict[str, Path] = {}
    for service in services:
        service_dir = models_dir / service
        if not service_dir.exists():
            continue
        versions = sorted(
            [p for p in service_dir.iterdir() if p.is_dir()], key=lambda p: p.name
        )
        if not versions:
            continue
        latest = versions[-1]
        candidate = latest / f"{service}-{latest.name}.json"
        if not candidate.exists():
            candidates = list(latest.glob("*.json"))
            if not candidates:
                continue
            candidate = candidates[0]
        resolved[service] = candidate
    return resolved
