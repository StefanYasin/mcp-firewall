"""A tiny MCP server over stdio for trying mcp-firewall without a real one.

Run it directly:

    python examples/echo_server.py

or put the firewall in front of it:

    python -m mcp_firewall --config policy.example.yml --server "python examples/echo_server.py"
"""

from __future__ import annotations

import json
import sys

TOOLS = [
    {
        "name": "echo",
        "description": "Echo the text argument back",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "add",
        "description": "Add two numbers",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
            "required": ["a", "b"],
        },
    },
    {
        "name": "delete_everything",
        "description": "A deliberately dangerous looking tool for policy demos",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def send(message: dict) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def text(value: str, is_error: bool = False) -> dict:
    result = {"content": [{"type": "text", "text": value}]}
    if is_error:
        result["isError"] = True
    return result


def handle(message: dict) -> None:
    method = message.get("method")
    if method is None or "id" not in message:
        return
    request_id = message["id"]
    params = message.get("params") or {}
    if method == "initialize":
        send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "echo-server", "version": "0.1.0"},
                },
            }
        )
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name == "echo":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": text(str(arguments.get("text", ""))),
                }
            )
        elif name == "add":
            total = arguments.get("a", 0) + arguments.get("b", 0)
            send({"jsonrpc": "2.0", "id": request_id, "result": text(str(total))})
        elif name == "delete_everything":
            send({"jsonrpc": "2.0", "id": request_id, "result": text("deleted")})
        else:
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": "unknown tool %r" % name},
                }
            )
    else:
        send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found: %s" % method},
            }
        )


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if line:
            message = json.loads(line)
            if isinstance(message, dict):
                handle(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
