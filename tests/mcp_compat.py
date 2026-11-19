"""Run the MCP tests on both mcp 1.x and mcp 2.x.

mcp 2 renamed ``FastMCP`` to ``MCPServer`` and replaced
``create_connected_server_and_client_session`` with ``mcp.Client``.
"""

from contextlib import asynccontextmanager


def server_class():
    try:
        from mcp.server.fastmcp import FastMCP

        return FastMCP
    except ImportError:
        from mcp.server.mcpserver import MCPServer

        return MCPServer


@asynccontextmanager
async def in_memory_session(app):
    """Yield a client connected to ``app`` in-process; it has an awaitable ``call_tool``."""
    try:
        from mcp.shared.memory import create_connected_server_and_client_session
    except ImportError:
        from mcp import Client

        async with Client(app) as client:
            yield client
    else:
        async with create_connected_server_and_client_session(app) as session:
            yield session
