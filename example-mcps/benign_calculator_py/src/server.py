"""MCP calculator — pure math, no IO, no network."""
import json
import math
from mcp.server import Server

server = Server("calculator")


@server.tool("add")
async def add(a: float, b: float) -> str:
    """Add two numbers together."""
    return json.dumps({"result": a + b})


@server.tool("multiply")
async def multiply(a: float, b: float) -> str:
    """Multiply two numbers together."""
    return json.dumps({"result": a * b})


@server.tool("sqrt")
async def sqrt(n: float) -> str:
    """Calculate the square root of a number."""
    if n < 0:
        return json.dumps({"error": "Cannot calculate square root of negative number"})
    return json.dumps({"result": math.sqrt(n)})


@server.tool("factorial")
async def factorial(n: int) -> str:
    """Calculate the factorial of a non-negative integer."""
    if n < 0:
        return json.dumps({"error": "Cannot calculate factorial of negative number"})
    if n > 170:
        return json.dumps({"error": "Number too large for factorial calculation"})
    return json.dumps({"result": math.factorial(n)})


def main():
    import asyncio
    from mcp.server.stdio import stdio_server

    async def run():
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(run())
