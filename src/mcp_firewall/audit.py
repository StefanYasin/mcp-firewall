"""JSONL audit logging and argument summarization."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REDACTED = "[redacted]"
SENSITIVE_NAMES = frozenset(
    {
        "authorization",
        "auth",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "key",
        "password",
        "passwd",
        "private_key",
        "secret",
        "session",
        "session_id",
        "token",
        "x-api-key",
    }
)
SENSITIVE_SUFFIXES = (
    "_api_key",
    "_apikey",
    "_cookie",
    "_credential",
    "_credentials",
    "_key",
    "_passwd",
    "_password",
    "_private_key",
    "_secret",
    "_token",
)


def is_sensitive(name: str) -> bool:
    lowered = name.lower()
    if lowered in SENSITIVE_NAMES:
        return True
    return lowered.endswith(SENSITIVE_SUFFIXES)


def clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "...[%d chars]" % (len(text) - limit)


def summarize(
    value: Any,
    *,
    max_string: int = 160,
    max_items: int = 8,
    max_depth: int = 3,
    _depth: int = 0,
) -> Any:
    """Return a small JSON friendly version of a tool argument value."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return clip(value, max_string)
    if _depth >= max_depth:
        return "<%s too deep>" % type(value).__name__
    if isinstance(value, dict):
        out: dict = {}
        items = list(value.items())
        for key, item in items[:max_items]:
            name = str(key)
            if is_sensitive(name):
                out[name] = REDACTED
            else:
                out[name] = summarize(
                    item,
                    max_string=max_string,
                    max_items=max_items,
                    max_depth=max_depth,
                    _depth=_depth + 1,
                )
        if len(items) > max_items:
            out["..."] = "%d more keys" % (len(items) - max_items)
        return out
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        out = [
            summarize(
                item,
                max_string=max_string,
                max_items=max_items,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
            for item in items[:max_items]
        ]
        if len(items) > max_items:
            out.append("... %d more items" % (len(items) - max_items))
        return out
    return clip(repr(value), max_string)


def summarize_arguments(arguments: Any, **kwargs) -> Any:
    return summarize(arguments, **kwargs)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditLog:
    """Append only JSONL writer. One line per event."""

    def __init__(
        self,
        path: str | Path,
        *,
        include_arguments: bool = True,
        max_string: int = 160,
    ) -> None:
        self.path = Path(path)
        self.include_arguments = include_arguments
        self.max_string = max_string
        self.records = 0
        self._lock = threading.Lock()
        self._handle = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a", encoding="utf-8", newline="\n")

    def emit(self, event: str, **fields: Any) -> dict:
        record = {"ts": _utc_now(), "event": event}
        record.update(fields)
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str)
        with self._lock:
            if self._handle is not None:
                self._handle.write(line + "\n")
                self._handle.flush()
                try:
                    os.fsync(self._handle.fileno())
                except OSError:
                    pass
            self.records += 1
        return record

    def tool_call(self, server: str, tool: str, arguments: Any, request_id: Any, decision) -> dict:
        fields: dict = {
            "server": server,
            "tool": tool,
            "request_id": request_id,
            "decision": "allow" if decision.allowed else "deny",
            "reason": decision.reason,
            "rule": decision.rule,
        }
        if decision.code is not None:
            fields["code"] = decision.code
        if decision.retry_after:
            fields["retry_after_seconds"] = round(decision.retry_after, 3)
        if self.include_arguments:
            fields["arguments"] = summarize_arguments(arguments, max_string=self.max_string)
            fields["argument_keys"] = sorted(arguments) if isinstance(arguments, dict) else []
            fields["argument_bytes"] = len(
                json.dumps(arguments, ensure_ascii=False, default=str)
            )
        return self.emit("tool_call", **fields)

    def tool_result(
        self,
        server: str,
        tool: str,
        request_id: Any,
        duration_ms: float,
        *,
        is_error: bool,
        summary: str,
    ) -> dict:
        return self.emit(
            "tool_result",
            server=server,
            tool=tool,
            request_id=request_id,
            duration_ms=round(duration_ms, 3),
            is_error=is_error,
            result=summary,
        )

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                self._handle.flush()
                self._handle.close()
                self._handle = None

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def read_records(path: str | Path) -> list[dict]:
    """Read a JSONL audit log into a list of records."""
    records = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
