import asyncio
from dataclasses import dataclass
from typing import Any, Callable


# Mock ToolSpec and ToolResult
@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, object]
    handler: Callable[[dict[str, object]], Any]

@dataclass
class ToolResult:
    content: str
    structured_content: dict[str, object] | None = None

# Mock FastMCP behavior (simplified)
class FastToolResult:
    def __init__(self, content: str, structured_content: dict[str, object] | None = None):
        self.content = content
        self.structured_content = structured_content

# The corrected _handler implementation wrapper
def create_handler(tool: ToolSpec):
    async def _handler(**kwargs: object) -> FastToolResult:
        result = tool.handler(kwargs)
        return FastToolResult(
            content=result.content,
            structured_content=result.structured_content,
        )
    return _handler

# Mock tool handler
def mock_execute_handler(payload: dict[str, object]) -> ToolResult:
    # Verify we got the arguments correctly
    if "service" in payload and "operation" in payload and "options" in payload:
        return ToolResult(content="Success", structured_content={"status": "ok"})
    return ToolResult(content="Error", structured_content={"error": "Missing keys"})

async def main():
    print("Testing handler with kwargs...")
    
    # Define tool
    tool = ToolSpec(
        name="aws_execute",
        description="test",
        input_schema={},
        handler=mock_execute_handler
    )
    
    # Create wrapped handler
    handler = create_handler(tool)
    
    # Simulate FastMCP calling the handler with kwargs (unpacked from JSON params)
    # This mimics:
    # await handler(service="s3", operation="DeleteObject", options={"confirmationToken": "abc"})
    try:
        result = await handler(
            service="s3",
            operation="DeleteObject",
            options={"confirmationToken": "abc"},
            payload={"Bucket": "foo", "Key": "bar"},
        )
        print(f"Result: {result.content}")
        if result.content == "Success":
            print("VERIFICATION PASSED: Handler accepted key-word arguments.")
        else:
            print("VERIFICATION FAILED: Handler returned error.")

    except TypeError as e:
        print(f"VERIFICATION FAILED: TypeError: {e}")
    except Exception as e:
        print(f"VERIFICATION FAILED: Unexpected error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
