"""End to end tests: a real gateway process in front of a real stdio server."""

from __future__ import annotations

ALLOW_ECHO = """
version: 1
default: deny
servers:
  fake:
    tools:
      allow: ["echo", "add"]
"""

ALLOW_AND_DENY = """
version: 1
default: deny
servers:
  fake:
    tools:
      allow: ["echo", "rm_rf", "add"]
      deny: ["rm_rf"]
"""


def test_allowed_call_is_forwarded_and_returns_the_server_result(make_session):
    session = make_session(ALLOW_ECHO)
    init = session.initialize()
    assert init["result"]["serverInfo"]["name"] == "fake-mcp-server"

    response = session.call("echo", {"text": "hello firewall"}, request_id=7)
    assert response["id"] == 7
    assert "result" in response
    assert "hello firewall" in response["result"]["content"][0]["text"]
    assert session.traced_calls() == ["echo"]


def test_denied_call_returns_an_error_and_never_reaches_the_server(make_session):
    session = make_session(ALLOW_AND_DENY)
    session.initialize()

    ok = session.call("echo", {"text": "warm up"}, request_id=1)
    assert "result" in ok

    denied = session.call("rm_rf", {"path": "/tmp/important"}, request_id=2)
    assert denied["id"] == 2
    assert "result" not in denied
    assert denied["error"]["code"] == -32001
    assert "rm_rf" in denied["error"]["message"]
    assert denied["error"]["data"]["tool"] == "rm_rf"
    assert denied["error"]["data"]["server"] == "fake"

    # The fake server writes a trace line before it handles a call. Only the
    # allowed call may appear there.
    assert session.traced_calls() == ["echo"]


def test_audit_log_records_allow_and_deny_with_argument_summaries(make_session):
    session = make_session(ALLOW_AND_DENY)
    session.initialize()

    long_text = "a" * 400
    session.call(
        "echo",
        {
            "text": long_text,
            "api_key": "sk-live-should-not-be-logged",
            "nested": {"password": "hunter2", "ok": 1},
        },
        request_id=11,
    )
    session.call("rm_rf", {"path": "/etc/passwd"}, request_id=12)
    session.close()

    records = session.records()
    calls = [record for record in records if record["event"] == "tool_call"]
    assert len(calls) == 2

    allowed, denied = calls
    assert allowed["tool"] == "echo"
    assert allowed["decision"] == "allow"
    assert allowed["rule"] == "allow:echo"
    assert allowed["request_id"] == 11
    assert allowed["argument_keys"] == ["api_key", "nested", "text"]
    assert allowed["arguments"]["api_key"] == "[redacted]"
    assert allowed["arguments"]["nested"]["password"] == "[redacted]"
    assert allowed["arguments"]["nested"]["ok"] == 1
    assert allowed["arguments"]["text"].endswith("...[240 chars]")
    assert len(allowed["arguments"]["text"]) < 200
    assert allowed["argument_bytes"] > 400

    assert denied["tool"] == "rm_rf"
    assert denied["decision"] == "deny"
    assert denied["code"] == -32001
    assert "deny rule" in denied["reason"]
    assert denied["arguments"]["path"] == "/etc/passwd"

    results = [record for record in records if record["event"] == "tool_result"]
    assert len(results) == 1
    assert results[0]["tool"] == "echo"
    assert results[0]["is_error"] is False
    assert results[0]["duration_ms"] >= 0.0

    events = [record["event"] for record in records]
    assert events[0] == "session_start"
    assert events[-1] == "session_end"
    assert records[-1]["allowed"] == 1
    assert records[-1]["denied"] == 1


def test_rate_limit_blocks_calls_after_the_quota(make_session):
    policy = """
version: 1
default: deny
servers:
  fake:
    tools:
      allow: "*"
    rate_limit:
      calls: 2
      per_seconds: 60
"""
    session = make_session(policy)
    session.initialize()

    assert "result" in session.call("echo", {"text": "one"}, request_id=1)
    assert "result" in session.call("echo", {"text": "two"}, request_id=2)
    limited = session.call("echo", {"text": "three"}, request_id=3)

    assert limited["error"]["code"] == -32002
    assert limited["error"]["data"]["rule"] == "rate_limit"
    assert limited["error"]["data"]["retry_after_seconds"] > 0
    assert session.traced_calls() == ["echo", "echo"]

    session.close()
    denied = [r for r in session.records() if r.get("decision") == "deny"]
    assert len(denied) == 1
    assert denied[0]["code"] == -32002


def test_tools_list_and_notifications_pass_through(make_session):
    session = make_session(ALLOW_ECHO)
    session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    listed = session.request("tools/list", request_id=5)
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert names == ["echo", "add", "rm_rf", "fail", "slow"]


def test_error_results_are_forwarded_and_logged(make_session):
    policy = """
version: 1
servers:
  fake:
    tools:
      allow: "*"
"""
    session = make_session(policy)
    response = session.call("fail", {}, request_id=3)
    assert response["result"]["isError"] is True
    session.close()
    results = session.events("tool_result")
    assert len(results) == 1
    assert results[0]["is_error"] is True


def test_invalid_json_is_forwarded_without_crashing(make_session):
    session = make_session(ALLOW_ECHO)
    session.initialize()
    session.send_raw(b"{not json}\n")
    reply = session.recv()
    assert reply["error"]["code"] == -32700

    still_alive = session.call("echo", {"text": "after bad json"}, request_id=9)
    assert "after bad json" in still_alive["result"]["content"][0]["text"]
    assert session.events("protocol_error")

def test_no_arguments_flag_keeps_payloads_out_of_the_log(make_session):
    session = make_session(ALLOW_ECHO, extra_args=("--no-arguments",))
    session.call("echo", {"text": "private value"}, request_id=1)
    session.close()
    calls = session.events("tool_call")
    assert len(calls) == 1
    assert "arguments" not in calls[0]
    assert "argument_bytes" not in calls[0]
    assert calls[0]["decision"] == "allow"
