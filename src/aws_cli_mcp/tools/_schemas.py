"""JSON Schema definitions and ToolSpec instances for the 3 unified AWS tools."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from aws_cli_mcp.mcp_runtime import ToolResult, ToolSpec

ToolHandler = Callable[[dict[str, object]], ToolResult | Awaitable[ToolResult]]

SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string",
            "minLength": 1,
            "maxLength": 256,
            "description": (
                "Search keywords to match against operation names or descriptions. "
                "Supports multiple keywords separated by space (e.g., 'lambda list'). "
                "All keywords must match (AND search). Case-insensitive."
            ),
        },
        "serviceHint": {
            "type": "string",
            "maxLength": 128,
            "description": (
                "AWS service name in lowercase. Examples: 'lambda', 'ec2', 's3', 'iam', "
                "'dynamodb', 'sqs', 'sns', etc. If omitted, searches across all allowed services."
            ),
        },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
            "default": 20,
            "description": "Maximum number of results to return (default: 20).",
        },
    },
    "required": ["query"],
    "additionalProperties": False,
}

GET_SCHEMA_SCHEMA = {
    "type": "object",
    "properties": {
        "service": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": (
                "AWS service name in lowercase. Examples: 'lambda', 's3', 'ec2', 'iam'. "
                "Use the exact service name returned from aws_search_operations."
            ),
        },
        "operation": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": (
                "AWS operation name. supports PascalCase (e.g. 'ListFunctions'), "
                "or kebab-case/snake_case (e.g. 'list-functions', 'list_functions'). "
                "The name is case-insensitive."
            ),
        },
    },
    "required": ["service", "operation"],
    "additionalProperties": False,
}

EXECUTE_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["validate", "invoke"],
            "description": (
                "'validate': Check payload against schema and policy without executing. "
                "'invoke': Validate and execute the AWS API call. "
                "Always use 'validate' first to catch errors before 'invoke'."
            ),
        },
        "service": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": (
                "AWS service name in lowercase. Examples: 'lambda', 's3', 'ec2', 'iam'. "
                "Must match the service name from aws_search_operations "
                "or aws_get_operation_schema."
            ),
        },
        "operation": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": (
                "AWS operation name. supports PascalCase (e.g. 'ListFunctions'), "
                "or kebab-case/snake_case (e.g. 'list-functions', 'list_functions'). "
                "The name is case-insensitive."
            ),
        },
        "payload": {
            "type": ["object", "string"],
            "description": (
                "Operation parameters as a JSON object (or JSON string). "
                "Use aws_get_operation_schema to see required/optional fields. "
                'Example for Lambda Invoke: {"FunctionName": "my-function"}. '
                "Use {} for operations with no required parameters."
            ),
        },
        "region": {
            "type": "string",
            "description": (
                "AWS region code. Examples: 'us-east-1', 'ap-northeast-1', 'eu-west-1'. "
                "Uses AWS_DEFAULT_REGION if not specified."
            ),
        },
        "options": {
            "type": ["object", "string"],
            "description": (
                "Execution options. For Identity Center, specify accountId + roleName "
                "(or roleArn) to select the role. Example: "
                "{'accountId': '123456789012', 'roleName': 'ReadOnly'}. "
                "Other options include confirmationToken for destructive operations. "
                "For large responses, responseMode ('auto'|'compact'|'full'), "
                "maxResultItems (int), and omitResponseFields (string array) are supported."
            ),
        },
    },
    "required": ["action", "service", "operation", "payload"],
    "additionalProperties": False,
}


def make_tool_specs(
    search_handler: ToolHandler,
    get_schema_handler: ToolHandler,
    execute_handler: ToolHandler,
) -> tuple[ToolSpec, ToolSpec, ToolSpec]:
    """Create the 3 ToolSpec instances with the given handler callables."""
    search_operations_tool = ToolSpec(
        name="aws_search_operations",
        description=(
            "Step 1: Search AWS operations from Smithy models. "
            "Use this first to find the correct service and operation names. "
            "Do NOT wrap arguments in a 'payload' object. "
            "Required: 'query' (string). Optional: 'serviceHint' (string), 'limit' (int). "
            "Examples:\n"
            "1. Simple: call(query='s3 list')\n"
            "2. Advanced: call(query='list', serviceHint='s3', limit=5)"
        ),
        input_schema=SEARCH_SCHEMA,
        handler=search_handler,
    )

    get_operation_schema_tool = ToolSpec(
        name="aws_get_operation_schema",
        description=(
            "Step 2: Get the JSON Schema for an AWS operation. "
            "Use this to check the required parameters and types before executing. "
            "Do NOT wrap arguments in a 'payload' object. "
            "Required: 'service' (string), 'operation' (string). "
            "Example: call(service='lambda', operation='CreateFunction')"
        ),
        input_schema=GET_SCHEMA_SCHEMA,
        handler=get_schema_handler,
    )

    execute_tool = ToolSpec(
        name="aws_execute",
        description=(
            "Validate and invoke AWS operations. "
            "Do NOT wrap arguments in a 'payload' object. "
            "Required top-level arguments: 'action' (enum: validate/invoke), "
            "'service' (string), 'operation' (string), 'payload' (object: API params). "
            "Optional: 'region' (string), 'options' (object: confirmationToken, "
            "accountId/roleName for Identity Center, responseMode/maxResultItems/"
            "omitResponseFields for large responses). "
            "\n\n"
            "LARGE RESPONSE RECOMMENDATION:\n"
            "- Default/recommended: options={'responseMode':'auto'}\n"
            "- For list APIs first try: options={'responseMode':'compact','maxResultItems':20}\n"
            "- For full fidelity: options={'responseMode':'full'} with narrower request scope\n\n"
            "BINARY DATA: For binary fields (Body, ZipFile, etc.), provide "
            "base64-encoded content as a string."
            "\n\n"
            "Examples:\n"
            "1. List Lambda Functions:\n"
            "   call(action='invoke', service='lambda', operation='ListFunctions', payload={})\n"
            "2. S3 Upload (base64 body):\n"
            "   call(action='invoke', service='s3', operation='PutObject',\n"
            "   payload={'Bucket': 'my-bucket', 'Key': 'file.txt', 'Body': 'SGVsbG8gV29ybGQ='})"
        ),
        input_schema=EXECUTE_SCHEMA,
        handler=execute_handler,
    )

    return search_operations_tool, get_operation_schema_tool, execute_tool
