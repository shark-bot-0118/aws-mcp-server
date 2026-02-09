"""Smithy model sync using aws/api-models-aws repository."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from aws_cli_mcp.config import SmithySettings

# Only allow safe git ref names (branches, tags, SHAs).
_SAFE_REF_RE = re.compile(r"^[a-zA-Z0-9._/+-]+$")

# Only allow HTTPS URLs for git sync (prevents file://, ssh://, etc.).
_SAFE_URL_RE = re.compile(r"^https://")


def _validate_sync_inputs(url: str, ref: str) -> None:
    """Validate sync_url and sync_ref to prevent argument injection / SSRF."""
    if not _SAFE_URL_RE.match(url):
        raise ValueError(f"sync_url must use HTTPS scheme, got: {url[:120]}")
    if not _SAFE_REF_RE.match(ref):
        raise ValueError(f"sync_ref contains invalid characters: {ref[:120]}")
    if ref.startswith("-"):
        raise ValueError(f"sync_ref must not start with '-': {ref[:120]}")


def sync_models(settings: SmithySettings) -> str:
    if not settings.sync_url:
        return settings.model_path
    if not settings.auto_sync:
        return settings.model_path

    _validate_sync_inputs(settings.sync_url, settings.sync_ref)

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
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except Exception:
        return None


_SUBPROCESS_TIMEOUT_SECONDS = 120


def _run(cmd: list[str]) -> None:
    try:
        result = subprocess.run(
            cmd, check=False, capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        subcmd = cmd[1] if len(cmd) > 1 else cmd[0]
        raise RuntimeError(f"git {subcmd} timed out after {_SUBPROCESS_TIMEOUT_SECONDS}s")
    if result.returncode != 0:
        # Only include the subcommand (e.g. "clone", "fetch") — never the full args
        # to avoid leaking repository URLs that may contain credentials.
        subcmd = cmd[1] if len(cmd) > 1 else cmd[0]
        raise RuntimeError(f"git {subcmd} failed (exit {result.returncode})")
