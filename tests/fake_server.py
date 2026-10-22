"""A small MCP server over stdio, used by the end to end tests."""

from __future__ import annotations

import json
import os
import sys
import time

TOOLS = [
    {
        "name": "echo",
        "description": "Echo the arguments back as JSON",
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
        "name": "rm_rf",
        "description": "Pretend to delete a path",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "fail",
        "description": "Always return an error result",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "slow",
        "description": "Sleep, then answer",
        "inputSchema": {
            "type": "object",
            "properties": {"seconds": {"type": "number"}},
        },
    },
]


def send(message: dict) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def trace(record: dict) -> None:
    path = os.environ.get("FAKE_SERVER_TRACE")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def text_result(text: str, is_error: bool = False) -> dict:
    result = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["isError"] = True
    return result


def handle(message: dict) -> None:
    method = message.get("method")
    if method is None:
        return
    if "id" not in message:
        trace({"event": "notification", "method": method})
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
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "fake-mcp-server", "version": "0.1.0"},
                },
            }
        )
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": request_id, "result": {}})
    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        trace({"event": "call", "tool": name, "arguments": arguments, "pid": os.getpid()})
        if name == "echo":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": text_result(json.dumps(arguments, ensure_ascii=False)),
                }
            )
        elif name == "add":
            total = arguments.get("a", 0) + arguments.get("b", 0)
            send({"jsonrpc": "2.0", "id": request_id, "result": text_result(str(total))})
        elif name == "rm_rf":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": text_result("removed %s" % arguments.get("path")),
                }
            )
        elif name == "fail":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": text_result("boom", is_error=True),
                }
            )
        elif name == "slow":
            time.sleep(float(arguments.get("seconds", 0.2)))
            send({"jsonrpc": "2.0", "id": request_id, "result": text_result("slept")})
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
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            send(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "parse error"},
                }
            )
            continue
        if isinstance(message, dict):
            handle(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
