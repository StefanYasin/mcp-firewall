from __future__ import annotations

import pytest

from mcp_firewall.policy import (
    DENIED_CODE,
    RATE_LIMITED_CODE,
    Enforcer,
    Policy,
    PolicyError,
    RateLimit,
    RateLimiter,
)


def build(text: str) -> Policy:
    from mcp_firewall import yaml_lite

    return Policy.from_dict(yaml_lite.loads(text))


def test_defaults_apply_to_every_server_and_unknown_names():
    policy = build(
        """
version: 1
default: deny
defaults:
  tools:
    allow: ["read_*"]
    deny: ["read_secrets"]
"""
    )
    assert policy.decide("anything", "read_file").allowed
    assert not policy.decide("anything", "read_secrets").allowed
    assert not policy.decide("anything", "write_file").allowed
    assert policy.decide("anything", "read_file").rule == "allow:read_*"


def test_server_block_overrides_only_the_keys_it_sets():
    policy = build(
        """
version: 1
default: deny
defaults:
  tools:
    allow: ["read_*"]
    deny: ["read_secrets"]
  rate_limit:
    calls: 100
    per_seconds: 60
servers:
  filesystem:
    tools:
      deny: ["read_env"]
"""
    )
    fs = policy.server("filesystem")
    assert fs.tools.allow == ("read_*",)
    assert fs.tools.deny == ("read_env",)
    assert fs.rate_limit == RateLimit(calls=100, per_seconds=60.0)
    assert not policy.decide("filesystem", "read_env").allowed
    assert policy.decide("filesystem", "read_file").allowed


def test_deny_wins_over_allow():
    policy = build(
        """
version: 1
servers:
  fake:
    tools:
      allow: ["*"]
      deny: ["delete_*", "rm_rf"]
"""
    )
    decision = policy.decide("fake", "delete_file")
    assert not decision.allowed
    assert decision.rule == "deny:delete_*"
    assert decision.code == DENIED_CODE
    assert policy.decide("fake", "read_file").allowed


def test_allow_list_rejects_everything_else():
    policy = build(
        """
version: 1
servers:
  fake:
    tools:
      allow: ["echo", "add"]
"""
    )
    decision = policy.decide("fake", "exec")
    assert not decision.allowed
    assert decision.rule == "allow:no-match"


def test_default_allow_when_no_rules_are_set():
    policy = build(
        """
version: 1
default: allow
servers:
  fake: {}
"""
    )
    decision = policy.decide("fake", "whatever")
    assert decision.allowed
    assert decision.rule == "default:allow"


def test_server_level_default_is_honored():
    policy = build(
        """
version: 1
default: deny
servers:
  fake:
    default: allow
"""
    )
    assert policy.decide("fake", "anything").allowed


def test_single_server_name_is_selected_by_default():
    policy = build(
        """
version: 1
servers:
  only:
    tools:
      allow: ["echo"]
"""
    )
    assert policy.default_server_name() == "only"


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("", "empty"),
        ("[]", "top level"),
        ("default: maybe", "'allow' or 'deny'"),
        ("servers: 5", "servers must be a mapping"),
        ("servers:\n  fake: 5", "servers.fake must be a mapping"),
        ("servers:\n  fake:\n    toolz: {}", "unknown key"),
        ("servers:\n  fake:\n    tools:\n      allow: 5", "list of tool names"),
        ("servers:\n  fake:\n    tools:\n      allow: [1]", "must contain strings"),
        ("servers:\n  fake:\n    rate_limit:\n      calls: 0", "positive integer"),
        (
            "servers:\n  fake:\n    rate_limit:\n      calls: 2\n      per_seconds: 0",
            "positive number",
        ),
        ("audit: 5", "audit must be a mapping"),
        ("defaults: 5", "defaults must be a mapping"),
    ],
)
def test_invalid_policies_are_rejected(text, fragment):
    with pytest.raises(PolicyError) as excinfo:
        build(text)
    assert fragment in str(excinfo.value)


def test_missing_policy_file_is_a_policy_error(tmp_path):
    with pytest.raises(PolicyError):
        Policy.load(tmp_path / "nope.yml")


def test_rate_limiter_uses_a_sliding_window():
    now = [100.0]
    limiter = RateLimiter(RateLimit(calls=2, per_seconds=10), clock=lambda: now[0])
    assert limiter.acquire() == (True, 0.0)
    now[0] = 101.0
    assert limiter.acquire() == (True, 0.0)
    allowed, retry = limiter.acquire()
    assert allowed is False
    assert retry == pytest.approx(9.0)
    now[0] = 111.0
    assert limiter.acquire()[0] is True


def test_enforcer_applies_rate_limit_after_policy():
    policy = build(
        """
version: 1
servers:
  fake:
    tools:
      allow: ["echo"]
    rate_limit: 2
"""
    )
    now = [0.0]
    enforcer = Enforcer(policy, clock=lambda: now[0])
    assert enforcer.check("fake", "echo").allowed
    assert enforcer.check("fake", "echo").allowed
    limited = enforcer.check("fake", "echo")
    assert not limited.allowed
    assert limited.code == RATE_LIMITED_CODE
    assert limited.retry_after == pytest.approx(60.0)
    # Denied calls do not consume quota.
    assert enforcer.check("fake", "rm_rf").code == DENIED_CODE
    now[0] = 60.0
    assert enforcer.check("fake", "echo").allowed
