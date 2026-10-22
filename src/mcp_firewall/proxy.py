"""A stdio proxy between an MCP client and one MCP server.

The client speaks newline delimited JSON-RPC on stdin/stdout. The server
runs as a child process. Every message is forwarded unless it is a
tools/call that the policy rejects, in which case the client gets a JSON-RPC
error and the call never reaches the server.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
import sys
import threading
import time
from typing import Any, BinaryIO

from .audit import AuditLog, clip
from .policy import Decision, Enforcer

log = logging.getLogger("mcp_firewall")

MAX_RESULT_SUMMARY = 200


def split_command(command: str | list[str] | tuple[str, ...]) -> list[str]:
    """Split a server command line without mangling Windows paths."""
    if isinstance(command, (list, tuple)):
        return [str(part) for part in command]
    text = command.strip()
    if not text:
        return []
    if '"' in text or "'" in text:
        parts = shlex.split(text, posix=False)
    else:
        parts = text.split()
    cleaned = []
    for part in parts:
        if len(part) >= 2 and part[0] == part[-1] and part[0] in "\"'":
            part = part[1:-1]
        cleaned.append(part)
    return cleaned


def _id_key(value: Any) -> str:
    try:
        rendered = json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        rendered = repr(value)
    return "%s:%s" % (type(value).__name__, rendered)


class Gateway:
    def __init__(
        self,
        enforcer: Enforcer,
        audit: AuditLog,
        server_command: str | list[str],
        server_name: str = "default",
        *,
        stdin: BinaryIO | None = None,
        stdout: BinaryIO | None = None,
        stderr: BinaryIO | None = None,
        policy_source: str = "",
    ) -> None:
        self.enforcer = enforcer
        self.audit = audit
        self.server_command = server_command
        self.name = server_name
        self.policy_source = policy_source
        self._stdin = stdin if stdin is not None else sys.stdin.buffer
        self._stdout = stdout if stdout is not None else sys.stdout.buffer
        self._stderr = stderr if stderr is not None else sys.stderr.buffer
        self._write_lock = threading.Lock()
        self._pending: dict[str, tuple[str, float, Any]] = {}
        self._pending_lock = threading.Lock()
        self._stop = threading.Event()
        self._counts = {"allow": 0, "deny": 0, "results": 0}

    def run(self) -> int:
        argv = split_command(self.server_command)
        if not argv:
            raise ValueError("server command is empty")
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        log.info("starting server: %s", " ".join(argv))
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=env,
        )
        self.audit.emit(
            "session_start",
            server=self.name,
            command=argv,
            pid=proc.pid,
            policy=self.policy_source,
        )
        reader = threading.Thread(
            target=self._pump_server, args=(proc,), name="mcp-firewall-server", daemon=True
        )
        reader.start()
        err_reader = threading.Thread(
            target=self._pump_stderr, args=(proc,), name="mcp-firewall-stderr", daemon=True
        )
        err_reader.start()
        try:
            self._client_loop(proc)
        except KeyboardInterrupt:  # pragma: no cover - interactive use
            log.info("interrupted")
        finally:
            code = self._shutdown(proc, reader, err_reader)
            self.audit.emit(
                "session_end",
                server=self.name,
                exit_code=code,
                allowed=self._counts["allow"],
                denied=self._counts["deny"],
                results=self._counts["results"],
            )
            self.audit.close()
        return code

    def _client_loop(self, proc: subprocess.Popen) -> None:
        while not self._stop.is_set():
            raw = self._stdin.readline()
            if not raw:
                break
            line = raw.strip()
            if not line:
                continue
            self._handle_client_line(line, proc)

    def _handle_client_line(self, line: bytes, proc: subprocess.Popen) -> None:
        try:
            message = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self.audit.emit(
                "protocol_error",
                server=self.name,
                error="invalid JSON from client: %s" % exc,
                raw=clip(line.decode("utf-8", "replace"), 200),
            )
            self._forward(line + b"\n", proc)
            return
        if isinstance(message, dict) and message.get("method") == "tools/call":
            self._handle_tool_call(message, line, proc)
            return
        self._forward(line + b"\n", proc)

    def _handle_tool_call(self, message: dict, line: bytes, proc: subprocess.Popen) -> None:
        params = message.get("params")
        request_id = message.get("id")
        has_id = "id" in message
        tool = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments", {}) if isinstance(params, dict) else {}

        if not isinstance(tool, str) or not tool:
            self.audit.emit(
                "invalid_tool_call",
                server=self.name,
                request_id=request_id,
                error="params.name is missing or not a string",
            )
            self._forward(line + b"\n", proc)
            return

        decision = self.enforcer.check(self.name, tool)
        self.audit.tool_call(self.name, tool, arguments, request_id, decision)

        if not decision.allowed:
            self._counts["deny"] += 1
            log.warning("denied %s: %s", tool, decision.reason)
            if has_id:
                self._write_client(self._error_response(request_id, tool, decision))
            return

        self._counts["allow"] += 1
        if has_id:
            with self._pending_lock:
                self._pending[_id_key(request_id)] = (tool, time.monotonic(), request_id)
        self._forward(line + b"\n", proc)

    def _error_response(self, request_id: Any, tool: str, decision: Decision) -> dict:
        if decision.code is None:
            prefix = "mcp-firewall: denied tool call %r: " % tool
        elif decision.retry_after:
            prefix = "mcp-firewall: rate limited tool call %r: " % tool
        else:
            prefix = "mcp-firewall: denied tool call %r: " % tool
        data = {
            "server": self.name,
            "tool": tool,
            "rule": decision.rule,
            "reason": decision.reason,
        }
        if decision.retry_after:
            data["retry_after_seconds"] = round(decision.retry_after, 3)
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": decision.code if decision.code is not None else -32001,
                "message": prefix + decision.reason,
                "data": data,
            },
        }

    def _forward(self, data: bytes, proc: subprocess.Popen) -> None:
        try:
            proc.stdin.write(data)
            proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            log.error("cannot write to server stdin: %s", exc)
            self._stop.set()

    def _pump_server(self, proc: subprocess.Popen) -> None:
        stream = proc.stdout
        if stream is None:  # pragma: no cover - defensive
            return
        while True:
            raw = stream.readline()
            if not raw:
                break
            line = raw.strip()
            if not line:
                continue
            self._handle_server_line(line)

    def _handle_server_line(self, line: bytes) -> None:
        try:
            message = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._write_client_bytes(line + b"\n")
            return
        if isinstance(message, dict) and "id" in message and "method" not in message:
            entry = None
            with self._pending_lock:
                entry = self._pending.pop(_id_key(message["id"]), None)
            if entry is not None:
                tool, started, request_id = entry
                self._counts["results"] += 1
                self.audit.tool_result(
                    self.name,
                    tool,
                    request_id,
                    (time.monotonic() - started) * 1000.0,
                    is_error=_is_error(message),
                    summary=_result_summary(message),
                )
        self._write_client_bytes(line + b"\n")

    def _pump_stderr(self, proc: subprocess.Popen) -> None:
        stream = proc.stderr
        if stream is None:  # pragma: no cover - defensive
            return
        while True:
            raw = stream.readline()
            if not raw:
                break
            try:
                self._stderr.write(raw)
                self._stderr.flush()
            except (BrokenPipeError, OSError, ValueError):  # pragma: no cover - defensive
                break

    def _write_client(self, message: dict) -> None:
        payload = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        self._write_client_bytes(payload.encode("utf-8") + b"\n")

    def _write_client_bytes(self, data: bytes) -> None:
        with self._write_lock:
            try:
                self._stdout.write(data)
                self._stdout.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                log.debug("client pipe closed: %s", exc)
                self._stop.set()

    def _shutdown(
        self,
        proc: subprocess.Popen,
        reader: threading.Thread,
        err_reader: threading.Thread | None = None,
    ) -> int:
        self._stop.set()
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass
        reader.join(timeout=3.0)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:  # pragma: no cover - stubborn server
                proc.kill()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    pass
        if err_reader is not None:
            err_reader.join(timeout=1.0)
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except (OSError, ValueError):
                pass
        code = proc.returncode or 0
        return 0 if code == 0 else code


def _is_error(message: dict) -> bool:
    if "error" in message:
        return True
    result = message.get("result")
    return isinstance(result, dict) and bool(result.get("isError"))


def _result_summary(message: dict) -> str:
    if "error" in message:
        error = message["error"]
        if isinstance(error, dict):
            return clip("error: %s" % (error.get("message", ""),), MAX_RESULT_SUMMARY)
        return clip("error: %r" % (error,), MAX_RESULT_SUMMARY)
    try:
        rendered = json.dumps(message.get("result"), ensure_ascii=False, default=str)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        rendered = repr(message.get("result"))
    return clip(rendered, MAX_RESULT_SUMMARY)
