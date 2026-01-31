"""Smithy model loader for local JSON bundles."""

from __future__ import annotations

import json
from pathlib import Path

from aws_cli_mcp.smithy.parser import SmithyModel, parse_model


def load_models(path: str) -> SmithyModel:
    model_path = Path(path)
    if not model_path.exists():
        raise FileNotFoundError(f"Smithy model path not found: {model_path}")
    return load_models_from_paths(_iter_json_files(model_path))


def load_models_from_paths(paths: list[Path]) -> SmithyModel:
    shapes = {}
    for file_path in paths:
        with file_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        model = parse_model(data)
        shapes.update(model.shapes)
    return SmithyModel(shapes=shapes)


def _iter_json_files(path: Path) -> list[Path]:
    if path.is_file() and path.suffix == ".json":
        return [path]
    if not path.is_dir():
        return []
    return sorted(path.glob("**/*.json"))
