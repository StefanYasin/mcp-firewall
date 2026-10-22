from __future__ import annotations

import json

from mcp_firewall.audit import AuditLog, is_sensitive, read_records, summarize
from mcp_firewall.policy import Decision


def test_sensitive_names():
    for name in ["api_key", "Authorization", "password", "db_password", "x-api-key"]:
        assert is_sensitive(name), name
    for name in ["path", "text", "max_tokens", "timeout", "user_id"]:
        assert not is_sensitive(name), name


def test_summarize_clips_redacts_and_limits():
    out = summarize(
        {
            "text": "x" * 300,
            "api_key": "secret",
            "items": list(range(20)),
            "nested": {"token": "abc", "keep": True},
        },
        max_string=50,
        max_items=4,
        max_depth=2,
    )
    assert out["text"] == "x" * 50 + "...[250 chars]"
    assert out["api_key"] == "[redacted]"
    assert out["items"] == [0, 1, 2, 3, "... 16 more items"]
    assert out["nested"] == {"token": "[redacted]", "keep": True}
    assert "..." not in out

    wide = summarize({"a": 1, "b": 2, "c": 3}, max_items=2)
    assert wide == {"a": 1, "b": 2, "...": "1 more keys"}


def test_summarize_depth_limit_and_unknown_types():
    out = summarize({"a": {"b": {"c": {"d": 1}}}}, max_depth=2)
    assert out["a"]["b"] == "<dict too deep>"
    assert summarize(b"bytes") == "b'bytes'"


def test_audit_log_writes_jsonl_and_appends(tmp_path):
    path = tmp_path / "nested" / "audit.jsonl"
    with AuditLog(path) as log:
        log.emit("session_start", server="fake", pid=1)
        log.tool_call(
            "fake",
            "echo",
            {"text": "hi", "api_key": "nope"},
            5,
            Decision(True, "tool matches allow rule 'echo'", "allow:echo"),
        )
        assert log.records == 2
    with AuditLog(path) as log:
        log.emit("session_end", server="fake", exit_code=0)

    records = read_records(path)
    assert [record["event"] for record in records] == [
        "session_start",
        "tool_call",
        "session_end",
    ]
    call = records[1]
    assert call["decision"] == "allow"
    assert call["arguments"]["api_key"] == "[redacted]"
    assert call["argument_keys"] == ["api_key", "text"]
    assert call["argument_bytes"] == len(json.dumps({"text": "hi", "api_key": "nope"}))


def test_audit_log_can_omit_arguments(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, include_arguments=False)
    log.tool_call(
        "fake",
        "echo",
        {"text": "hi"},
        1,
        Decision(False, "denied", "deny:echo", -32001),
    )
    log.close()
    record = read_records(path)[0]
    assert "arguments" not in record
    assert "argument_bytes" not in record
    assert record["decision"] == "deny"
    assert record["code"] == -32001
