"""Convenience entrypoint for launching the AWS CLI MCP server."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from aws_cli_mcp.server import run_entrypoint

if __name__ == "__main__":
    run_entrypoint()
