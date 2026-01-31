# AWS Tool-Execution MCP Server

A robust, enterprise-grade Model Context Protocol (MCP) server that empowers LLMs to safely interact with your AWS environment. Built with a **"Validate-then-Invoke"** architecture and a **Dual Permission System**, it provides a secure bridge between AI agents and AWS infrastructure.

## 🌟 Key Features

*   **🛡️ Dual Permission System**: Security enforced at two levels—AWS IAM (Cloud) and `policy.yaml` (Local). Deny rules always take precedence.
*   **🚦 Human-in-the-Loop Safety**: Destructive operations (delete, terminate, stop) automatically trigger a confirmation flow, preventing accidental data loss.
*   **🔁 Dynamic Capabilities**: Access almost any AWS service (S3, Lambda, EC2, DynamoDB, etc.) dynamically powered by AWS Smithy models. No hardcoded tools.
*   **📂 Local File Integration**: Seamlessly upload local files and folders to S3 or Lambda using the `$path` syntax.
*   **📝 Audit Logging**: All interactions are audited locally with transaction IDs and operation details for full traceability.
*   **✅ 3-Tool Architecture**: Simplifies the context window by exposing only three unified tools instead of hundreds of individual functions.

---

## � Getting Started

### Prerequisites

*   **Python 3.11+**
*   **AWS CLI** installed and configured (or valid environment variables).
*   **MCP Client** (e.g., Claude Desktop, Zed, or any MCP-compatible agent).

### Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/your-org/aws-cli-mcp.git
    cd aws-cli-mcp
    ```

2.  **Install dependencies**:
    ```bash
    pip install -e .
    ```

3.  **Configure Environment**:
    Copy the example configuration:
    ```bash
    cp .env.example .env
    ```
    Edit `.env` to match your setup (see [Configuration](#-configuration) below).

### Running the Server

You can run the server directly via Python:

```bash
python server.py
```

Or configure it in your MCP Client (e.g., `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "aws": {
      "command": "/path/to/venv/bin/python",
      "args": ["/path/to/aws-cli-mcp/server.py"]
    }
  }
}
```

---

## 🛠 Usage Guide

The server exposes **3 core tools** that handle the entire workflow. This design ensures that the LLM first understands *what* it can do and *how* to do it before execution.

### 1. `aws.searchOperations`
**Purpose**: Find the correct AWS service and operation name.
*   **Input**: `{"query": "list buckets", "serviceHint": "s3"}`
*   **Output**: A list of matching operations (e.g., `s3:ListBuckets`) with descriptions and risk levels.

### 2. `aws.getOperationSchema`
**Purpose**: Get the strict JSON Schema for a specific operation.
*   **Input**: `{"service": "s3", "operation": "ListBuckets"}`
*   **Output**: Full parameter definition, including required fields and type constraints.

### 3. `aws.execute`
**Purpose**: The single entry point for validation and execution.
*   **Action `validate`**: checks permissions and strict parameter validity without making network calls.
*   **Action `invoke`**: performs the actual AWS API call.

### Typical Workflow Example

**User**: "Listing my S3 buckets."

1.  **Search**: Agent calls `aws.searchOperations(query="list buckets")`.
    *   *Result*: Finds `s3:ListBuckets`.
2.  **Schema**: Agent calls `aws.getOperationSchema(service="s3", operation="ListBuckets")`.
    *   *Result*: Receives schema showing optional parameters like `BucketRegion`.
3.  **Execute**: Agent calls `aws.execute(action="invoke", service="s3", operation="ListBuckets", payload={})`.
    *   *Result*: Returns the list of buckets.

---

## 🔐 Security & Policy

This server is designed with a **"Defense in Depth"** approach.

### 1. Policy Configuration (`policy.yaml`)
You explicitly define what is allowed. By default, the policy should be restrictive.

```yaml
services:
  allowlist:
    - s3
    - lambda
    - ec2
  denylist:
    - iam # Explicitly block sensitive services

rules:
  allow:
    - "^s3:List.*"    # Allow listing
    - "^s3:Get.*"     # Allow reading
  deny:
    - "^.*:Delete.*"  # Global deny on deletion (overrides allow)

destructive_patterns:
  - "Delete"
  - "Terminate"
```

### 2. Destructive Operation Protection
If an operation matches a `destructive_pattern` (e.g., `DeleteBucket`) and is NOT in the `rules.deny` list, the server will **pause execution**.

1.  The server returns a `ConfirmationRequired` error with a unique **Confirmation Token**.
2.  The User must explicitly approve the action.
3.  The Agent must re-submit the request with `{"options": {"confirmationToken": "..."}}`.

---

## � Advanced: Local File Integration

The server supports a special `$path` syntax to handle local files securely, solving the problem of passing large binaries to LLMs.

### uploading a File
To upload a local file to S3 or use it in a Lambda function:

```json
{
  "service": "s3",
  "operation": "PutObject",
  "payload": {
    "Bucket": "my-bucket",
    "Key": "images/photo.png",
    "Body": { "$path": "/Users/me/Desktop/photo.png" }
  }
}
```

### Uploading a Folder
The server automatically handles folder uploads (recursive S3 put or zipping for Lambda):

```json
{
  "service": "lambda",
  "operation": "CreateFunction",
  "payload": {
    "FunctionName": "my-api",
    "Code": { "ZipFile": { "$path": "/Users/me/projects/my-api" } }
  }
}
```

---

## ⚙️ Configuration

Create a `.env` file in the root directory.

| Variable | Required | Description | Default |
| :--- | :---: | :--- | :--- |
| `AWS_PROFILE` | No | AWS CLI profile to use | `default` |
| `AWS_REGION` | No | Default AWS region | `us-east-1` |
| `LOG_LEVEL` | No | `DEBUG`, `INFO`, `WARNING` | `INFO` |
| `SMITHY_AUTO_SYNC` | No | Auto-update AWS models on startup | `true` |
| `AWS_MCP_AUTO_APPROVE_DESTRUCTIVE` | No | **DANGER**: Skip confirmation prompts | `false` |

---

## ❓ Troubleshooting

**Q: "Operation not found" error?**
A: Ensure the service is in your `policy.yaml` allowlist. If strict mode is on, unrecognized services are hidden.

**Q: "Access Denied" from AWS?**
A: Trace the error:
1.  Check `policy.yaml`: Did the MCP server block it?
2.  Check AWS IAM: Does your `AWS_PROFILE` user have permission?

**Q: Models are out of date?**
A: Set `SMITHY_AUTO_SYNC=true` in `.env` and restart. The server will pull the latest definitions from AWS.

---

## 🏗 Development

### Architecture
*   **`src/aws_cli_mcp/policy`**: Policy engine logic.
*   **`src/aws_cli_mcp/smithy`**: AWS model parsing and schema generation.
*   **`src/aws_cli_mcp/execution`**: Request handling and audit logging.

### Testing
Run the test suite:
```bash
pytest tests/
```

---

## 📜 License
MIT
