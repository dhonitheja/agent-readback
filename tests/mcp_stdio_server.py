"""Offline FastMCP fixture with an appointment store shared via SQLite.

Usage: mcp_stdio_server.py DATABASE [PORT]. Without PORT it speaks stdio; with
PORT it serves Streamable HTTP on 127.0.0.1 only.
"""

import inspect
import sqlite3
import sys
from contextlib import closing

try:
    from mcp.server.fastmcp import FastMCP as Server  # mcp 1.x
except ImportError:
    from mcp.server.mcpserver import MCPServer as Server  # mcp 2.x

app = Server("scheduler")


@app.tool()
def book_appointment(patient: str, practitioner: str, start: str, end: str) -> str:
    """Book an appointment in the fixture database."""
    with closing(sqlite3.connect(sys.argv[1])) as connection, connection:
        connection.execute(
            "INSERT INTO appointments (patient, practitioner, start, end) VALUES (?, ?, ?, ?)",
            (patient, practitioner, start, end),
        )
    return "Booked."


if __name__ == "__main__":
    if len(sys.argv) < 3:
        app.run(transport="stdio")
    else:  # second argument: serve Streamable HTTP on 127.0.0.1:<port> instead
        port = int(sys.argv[2])
        if "port" in inspect.signature(app.run_streamable_http_async).parameters:  # mcp 2.x
            app.run(transport="streamable-http", host="127.0.0.1", port=port)
        else:  # mcp 1.x reads host and port from settings
            app.settings.host, app.settings.port = "127.0.0.1", port
            app.run(transport="streamable-http")
