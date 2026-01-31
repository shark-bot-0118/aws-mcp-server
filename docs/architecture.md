# AWS Tool-Execution MCP Server Architecture

## Goals
- Provide Plan/Diff/Apply workflow for AWS operations via MCP.
- Enforce policy-as-code guardrails with destructive defaults denied.
- Require approval for risky operations when configured.
- Generate operation schemas from AWS Smithy models.
- Persist audit logs for every execution with tx_id/op_id.

## High-Level Components

### MCP Server Runtime
- Uses FastMCP when installed; otherwise a minimal MCP-compatible stdio server.
- Registers catalog, plan/diff/apply, approval tools, and optionally per-operation tools.

### Smithy Model Pipeline
- Loads local Smithy JSON models (stub path by default).
- Parses shapes into an in-memory catalog.
- Generates strict JSON Schemas for tool inputs.

### Policy Engine
- Evaluates allow/deny regex rules.
- Denies destructive operations by default unless explicitly allowed.
- Enforces required tags and approval for risk levels.

### Planning & Approval
- Plan creation validates schema and policy, storing Draft/Planned/Failed states.
- Approval requests are persisted with TTL and must be granted before apply when required.

### Execution & Idempotency
- Execution injects idempotency tokens when Smithy traits demand them.
- Uses boto3 for API calls with bounded retries.

### Audit & Artifacts
- SQLite stores plans, approvals, audit tx/op, and artifact references.
- File-based artifact store keeps redacted requests and full responses.

## Data Flow
1. Client searches catalog or uses operation tool to create a plan.
2. Server validates schema and policy, storing plan state.
3. Client requests approval if required.
4. Client applies plan; execution logs tx/op entries and artifacts.

## Directory Structure (Core)
```
aws_cli_v2/
├── docs/
│   └── architecture.md
├── policy.yaml
├── src/
│   └── aws_cli_mcp/
│       ├── app.py
│       ├── audit/
│       ├── execution/
│       ├── planning/
│       ├── policy/
│       ├── smithy/
│       ├── tools/
│       └── server.py
├── pyproject.toml
├── README.md
└── .env.example
```

## Open Questions
- Smithy sync (api-models-aws) integration and caching strategy.
- Describe-based diff mapping for each operation.
