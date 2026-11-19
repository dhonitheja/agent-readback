"""Offline FastMCP fixture with an appointment store shared via SQLite."""

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
    app.run(transport="stdio")
