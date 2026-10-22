"""Shared fixtures. The end to end tests drive the real CLI over pipes."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

FAKE_SERVER = Path(__file__).resolve().with_name("fake_server.py")


class GatewaySession:
    """A running mcp-firewall process talking to the fake MCP server."""

    def __init__(
        self,
        tmp_path: Path,
        policy_text: str,
        *,
        name: str | None = None,
        extra_args: tuple[str, ...] = (),
        server_command: str | None = None,
        include_audit_arg: bool = True,
        env_extra: dict[str, str] | None = None,
    ) -> None:
        self.tmp_path = Path(tmp_path)
        self.policy_path = self.tmp_path / "policy.yml"
        self.policy_path.write_text(policy_text, encoding="utf-8")
        self.audit_path = self.tmp_path / "audit.jsonl"
        self.trace_path = self.tmp_path / "trace.jsonl"
        self.stderr_lines: list[str] = []
        self._lines: queue.Queue = queue.Queue()

        command = [sys.executable, "-m", "mcp_firewall", "--config", str(self.policy_path)]
        if include_audit_arg:
            command += ["--audit", str(self.audit_path)]
        if name:
            command += ["--name", name]
        command += list(extra_args)
        command += [
            "--server",
            server_command or "%s %s" % (sys.executable, FAKE_SERVER),
        ]

        env = os.environ.copy()
        env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONUNBUFFERED"] = "1"
        env["FAKE_SERVER_TRACE"] = str(self.trace_path)
        if env_extra:
            env.update(env_extra)

        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(ROOT),
            env=env,
        )
        self._out_thread = threading.Thread(target=self._pump_stdout, daemon=True)
        self._out_thread.start()
        self._err_thread = threading.Thread(target=self._pump_stderr, daemon=True)
        self._err_thread.start()

    def _pump_stdout(self) -> None:
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            self._lines.put(raw)
        self._lines.put(None)

    def _pump_stderr(self) -> None:
        assert self.proc.stderr is not None
        for raw in self.proc.stderr:
            self.stderr_lines.append(raw.decode("utf-8", "replace"))

    def stderr(self) -> str:
        return "".join(self.stderr_lines)

    def send(self, message: dict) -> None:
        self.send_raw(json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n")

    def send_raw(self, payload: bytes) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(payload)
        self.proc.stdin.flush()

    def recv(self, timeout: float = 20.0) -> dict:
        try:
            raw = self._lines.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError(
                "no response in %.1fs\nstderr:\n%s" % (timeout, self.stderr())
            ) from None
        if raw is None:
            raise AssertionError("gateway closed stdout\nstderr:\n%s" % self.stderr())
        return json.loads(raw)

    def request(self, method: str, params: dict | None = None, request_id: int = 1) -> dict:
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)
        return self.recv()

    def initialize(self, request_id: int = 0) -> dict:
        return self.request("initialize", {"protocolVersion": "2024-11-05"}, request_id)

    def call(self, tool: str, arguments: dict | None = None, request_id: int = 1) -> dict:
        return self.request(
            "tools/call",
            {"name": tool, "arguments": arguments or {}},
            request_id,
        )

    def records(self) -> list[dict]:
        if not self.audit_path.exists():
            return []
        out = []
        for line in self.audit_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out

    def events(self, name: str) -> list[dict]:
        return [record for record in self.records() if record.get("event") == name]

    def traced_calls(self) -> list[str]:
        if not self.trace_path.exists():
            return []
        out = []
        for line in self.trace_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                if record.get("event") == "call":
                    out.append(record.get("tool"))
        return out

    def close(self, timeout: float = 20.0) -> int | None:
        if self.proc.poll() is None:
            try:
                if self.proc.stdin is not None:
                    self.proc.stdin.close()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        self._out_thread.join(timeout=5)
        self._err_thread.join(timeout=5)
        for stream in (self.proc.stdout, self.proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
        return self.proc.returncode

    def __enter__(self) -> "GatewaySession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@pytest.fixture
def make_session(tmp_path: Path):
    sessions: list[GatewaySession] = []

    def factory(policy_text: str, **kwargs) -> GatewaySession:
        session = GatewaySession(tmp_path, policy_text, **kwargs)
        sessions.append(session)
        return session

    yield factory
    for session in sessions:
        session.close()
