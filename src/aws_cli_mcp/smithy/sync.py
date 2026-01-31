"""Smithy model sync using aws/api-models-aws repository."""

from __future__ import annotations

import subprocess
from pathlib import Path

from aws_cli_mcp.config import SmithySettings


def sync_models(settings: SmithySettings) -> str:
    if not settings.sync_url:
        return settings.model_path
    if not settings.auto_sync:
        return settings.model_path

    cache_path = Path(settings.cache_path)
    repo_path = cache_path / "api-models-aws"
    cache_path.mkdir(parents=True, exist_ok=True)

    if not repo_path.exists():
        _run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                settings.sync_ref,
                settings.sync_url,
                str(repo_path),
            ]
        )
    else:
        _run(["git", "-C", str(repo_path), "fetch", "--depth", "1", "origin", settings.sync_ref])
        _run(["git", "-C", str(repo_path), "checkout", settings.sync_ref])
        _run(["git", "-C", str(repo_path), "reset", "--hard", f"origin/{settings.sync_ref}"])

    return str(repo_path / "models")


def get_model_commit_sha(cache_path: str) -> str | None:
    """Get the current commit SHA from the cached Smithy models repository.

    Args:
        cache_path: Path to the Smithy cache directory (parent of api-models-aws).

    Returns:
        The HEAD commit SHA as a string, or None if not a git repository.
    """
    repo_path = Path(cache_path) / "api-models-aws"
    if not repo_path.exists():
        return None

    git_dir = repo_path / ".git"
    if not git_dir.exists():
        return None

    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except Exception:
        return None


def _run(cmd: list[str]) -> None:
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
