
import asyncio
import inspect
import sys
from typing import Any

# Try to import fastmcp
try:
    from fastmcp import FastMCP
    from fastmcp.tools import FunctionTool
except ImportError:
    print("FastMCP not found, skipping specific FastMCP test")
    sys.exit(0)

async def main():
    print("Testing FastMCP with **kwargs...")

    async def bad_handler(**kwargs: Any) -> str:
        return "ok"

    try:
        FunctionTool.from_function(bad_handler, name="bad_tool", description="desc")
        print("UNEXPECTED: bad_handler (kwargs) was accepted")
    except ValueError as e:
        print(f"EXPECTED: bad_handler failed: {e}")

    print("\nTesting FastMCP with __signature__ spoofing...")
    
    async def spoofed_handler(**kwargs: Any) -> str:
        return "ok"
    
    # Spoof signature
    params = [
        inspect.Parameter("arg1", inspect.Parameter.KEYWORD_ONLY, annotation=str),
        inspect.Parameter("arg2", inspect.Parameter.KEYWORD_ONLY, annotation=int)
    ]
    spoofed_handler.__signature__ = inspect.Signature(params)
    
    try:
        FunctionTool.from_function(spoofed_handler, name="spoofed_tool", description="desc")
        print("SUCCESS: spoofed_handler was accepted!")
    except Exception as e:
        print(f"FAILED: spoofed_handler failed: {e}")

    print("\nTesting with dynamic function generation (exec)...")
    
    async def real_handler(payload: dict[str, Any]) -> str:
        return "ok"

    tool_name = "dynamic_tool"
    arg_names = ["x", "y"]
    
    # Create the function string
    args_str = ", ".join(f"{name}: object = None" for name in arg_names)
    code = f"""
async def generated_handler({args_str}) -> str:
    kwargs = locals()
    return await real_handler(kwargs)
"""
    local_scope = {"real_handler": real_handler}
    exec(code, {}, local_scope)
    generated_handler = local_scope["generated_handler"]
    
    try:
        FunctionTool.from_function(generated_handler, name="dynamic_tool", description="desc")
        print("SUCCESS: generated_handler was accepted!")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"FAILED: generated_handler failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())
