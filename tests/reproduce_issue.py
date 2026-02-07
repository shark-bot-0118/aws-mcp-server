
import asyncio
import json
import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

from aws_cli_mcp.app import AppContext
from aws_cli_mcp.audit.artifacts import ArtifactStore
from aws_cli_mcp.audit.db import SqliteStore
from aws_cli_mcp.config import Settings
from aws_cli_mcp.tools.aws_unified import execute_operation

# Setup test environment
TEST_DIR = Path("./test_data")
ARTIFACT_PATH = TEST_DIR / "artifacts"
SQLITE_PATH = TEST_DIR / "test.db"

def setup():
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)
    TEST_DIR.mkdir(parents=True)
    ARTIFACT_PATH.mkdir(parents=True)

def teardown():
    # if TEST_DIR.exists():
    #     shutil.rmtree(TEST_DIR)
    pass

async def reproduce():
    setup()
    
    # Mock dependencies
    settings = Settings()
    settings.storage.artifact_path = str(ARTIFACT_PATH)
    settings.storage.sqlite_path = str(SQLITE_PATH)
    settings.server.transport_mode = "http" # Force async behavior for artifacts
    
    store = SqliteStore(str(SQLITE_PATH))
    artifacts = ArtifactStore(str(ARTIFACT_PATH))
    
    # Mock App Context
    ctx = MagicMock(spec=AppContext)
    ctx.settings = settings
    ctx.store = store
    ctx.artifacts = artifacts
    ctx.policy_engine = MagicMock()
    ctx.policy_engine.evaluate.return_value.allowed = True
    ctx.policy_engine.evaluate.return_value.require_approval = False
    
    # Mock boto3 call to return sensitive data
    sensitive_value = "SUPER_SECRET_VALUE"
    mock_response = {"SecretString": sensitive_value}
    
    with patch("aws_cli_mcp.tools.aws_unified.get_app_context", return_value=ctx), \
         patch("aws_cli_mcp.tools.aws_unified.get_client_async"), \
         patch("aws_cli_mcp.tools.aws_unified.call_aws_api_async", return_value=mock_response), \
         patch("aws_cli_mcp.tools.aws_unified._resolve_snapshot") as mock_resolve:
         
        # Mock snapshot
        mock_model = MagicMock()
        mock_snapshot = MagicMock()
        mock_snapshot.model = mock_model
        mock_snapshot.catalog.find_operation.return_value.operation_shape_id = "op_id"
        mock_resolve.return_value = (mock_snapshot, "latest")
        
        # Execute
        payload = {
            "action": "invoke",
            "service": "secretsmanager",
            "operation": "GetSecretValue",
            "payload": {"SecretId": "my-secret"}
        }
        
        print("Executing operation...")
        result = await execute_operation(payload)
        
        # Check artifacts
        print("Checking artifacts...")
        found_sensitive = False
        for file in ARTIFACT_PATH.glob("*.json"):
            content = file.read_text()
            if sensitive_value in content:
                print(f"[FAIL] Found sensitive value in {file.name}")
                found_sensitive = True
            else:
                 print(f"[pass] Safe content in {file.name}")

        if found_sensitive:
            print("Reproduction SUCCESS: Sensitive data execution leaked to artifacts.")
        else:
            print("Reproduction FAILED: Sensitive data NOT found in artifacts.")

if __name__ == "__main__":
    asyncio.run(reproduce())
