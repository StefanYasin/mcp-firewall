"""Policy parsing, tool call decisions, and rate limiting."""

from __future__ import annotations

import fnmatch
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from . import yaml_lite

DENIED_CODE = -32001
RATE_LIMITED_CODE = -32002

_TOP_KEYS = {"version", "default", "defaults", "servers", "audit"}
_SERVER_KEYS = {"tools", "rate_limit", "default"}
_TOOLS_KEYS = {"allow", "deny", "default"}
_AUDIT_KEYS = {"path", "include_arguments"}
_RATE_KEYS = {"calls", "per_seconds"}
_ACTIONS = {"allow", "deny"}


class PolicyError(ValueError):
    """Raised when a policy file is missing fields or has the wrong shape."""


@dataclass(frozen=True)
class Decision:
    """The outcome of applying the policy to one tool call."""

    allowed: bool
    reason: str
    rule: str = "default"
    code: int | None = None
    retry_after: float = 0.0

    def as_dict(self) -> dict:
        out = {"allowed": self.allowed, "reason": self.reason, "rule": self.rule}
        if self.code is not None:
            out["code"] = self.code
        if self.retry_after:
            out["retry_after_seconds"] = round(self.retry_after, 3)
        return out


@dataclass(frozen=True)
class ToolsRule:
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    default: str = "deny"

    def matches_deny(self, tool: str) -> str | None:
        return _first_match(self.deny, tool)

    def matches_allow(self, tool: str) -> str | None:
        return _first_match(self.allow, tool)


@dataclass(frozen=True)
class RateLimit:
    calls: int
    per_seconds: float = 60.0

    def describe(self) -> str:
        return "%d calls per %gs" % (self.calls, self.per_seconds)


@dataclass(frozen=True)
class ServerPolicy:
    name: str
    tools: ToolsRule = field(default_factory=ToolsRule)
    rate_limit: RateLimit | None = None

    def as_dict(self) -> dict:
        out = {
            "allow": list(self.tools.allow),
            "deny": list(self.tools.deny),
            "default": self.tools.default,
        }
        if self.rate_limit is not None:
            out["rate_limit"] = {
                "calls": self.rate_limit.calls,
                "per_seconds": self.rate_limit.per_seconds,
            }
        return out


@dataclass(frozen=True)
class AuditConfig:
    path: str | None = None
    include_arguments: bool = True


class Policy:
    """A parsed policy file."""

    def __init__(
        self,
        servers: dict[str, ServerPolicy],
        fallback: ServerPolicy,
        audit: AuditConfig | None = None,
        source: str = "<policy>",
    ) -> None:
        self.servers = dict(servers)
        self.fallback = fallback
        self.audit = audit or AuditConfig()
        self.source = source

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError("cannot read policy %s: %s" % (p, exc.strerror or exc)) from None
        try:
            raw = yaml_lite.loads(text)
        except yaml_lite.YamlError as exc:
            raise PolicyError("%s: %s" % (p, exc)) from None
        return cls.from_dict(raw, source=str(p))

    @classmethod
    def from_dict(cls, raw: Any, source: str = "<policy>") -> "Policy":
        if raw is None:
            raise PolicyError("%s: policy is empty" % source)
        if not isinstance(raw, dict):
            raise PolicyError("%s: policy must be a mapping at the top level" % source)
        _reject_unknown(raw, _TOP_KEYS, "policy", source)

        top_default = _action(raw.get("default", "deny"), "default", source)

        defaults_raw = raw.get("defaults") or {}
        if not isinstance(defaults_raw, dict):
            raise PolicyError("%s: defaults must be a mapping" % source)
        _reject_unknown(defaults_raw, _SERVER_KEYS, "defaults", source)
        fallback = _build_server("defaults", defaults_raw, None, top_default, source)

        servers_raw = raw.get("servers") or {}
        if not isinstance(servers_raw, dict):
            raise PolicyError("%s: servers must be a mapping of name to policy" % source)
        servers: dict[str, ServerPolicy] = {}
        for name, block in servers_raw.items():
            if not isinstance(block, dict):
                raise PolicyError(
                    "%s: servers.%s must be a mapping" % (source, name)
                )
            servers[str(name)] = _build_server(
                str(name), block, fallback, top_default, source
            )

        audit = _build_audit(raw.get("audit"), source)
        return cls(servers, fallback, audit, source)

    def server(self, name: str) -> ServerPolicy:
        return self.servers.get(name, self.fallback)

    def default_server_name(self) -> str:
        if "default" in self.servers:
            return "default"
        if len(self.servers) == 1:
            return next(iter(self.servers))
        return "default"

    def decide(self, server: str, tool: str) -> Decision:
        rule = self.server(server).tools
        deny = rule.matches_deny(tool)
        if deny is not None:
            return Decision(False, "tool matches deny rule %r" % deny, "deny:%s" % deny, DENIED_CODE)
        allow = rule.matches_allow(tool)
        if allow is not None:
            return Decision(True, "tool matches allow rule %r" % allow, "allow:%s" % allow)
        if rule.allow:
            return Decision(
                False,
                "tool is not in the allow list for server %r" % server,
                "allow:no-match",
                DENIED_CODE,
            )
        if rule.default == "allow":
            return Decision(True, "no rule matched, default is allow", "default:allow")
        return Decision(False, "no rule matched, default is deny", "default:deny", DENIED_CODE)

    def summary(self, selected: str | None = None) -> dict:
        out: dict = {
            "source": self.source,
            "default": self.fallback.tools.default,
            "audit": {
                "path": self.audit.path,
                "include_arguments": self.audit.include_arguments,
            },
            "servers": {name: policy.as_dict() for name, policy in sorted(self.servers.items())},
        }
        if selected is not None:
            out["selected_server"] = selected
            out["effective"] = self.server(selected).as_dict()
        return out


def _first_match(patterns: Iterable[str], tool: str) -> str | None:
    for pattern in patterns:
        if pattern == tool or fnmatch.fnmatchcase(tool, pattern):
            return pattern
    return None


def _reject_unknown(raw: dict, allowed: set[str], label: str, source: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise PolicyError(
            "%s: unknown key(s) in %s: %s (allowed: %s)"
            % (source, label, ", ".join(unknown), ", ".join(sorted(allowed)))
        )


def _action(value: Any, label: str, source: str) -> str:
    if value is None:
        return "deny"
    if not isinstance(value, str) or value.strip().lower() not in _ACTIONS:
        raise PolicyError(
            "%s: %s must be 'allow' or 'deny', got %r" % (source, label, value)
        )
    return value.strip().lower()


def _string_list(value: Any, label: str, source: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        raise PolicyError("%s: %s must be a list of tool names" % (source, label))
    out = []
    for item in value:
        if not isinstance(item, str):
            raise PolicyError("%s: %s must contain strings, got %r" % (source, label, item))
        item = item.strip()
        if not item:
            raise PolicyError("%s: %s contains an empty tool name" % (source, label))
        out.append(item)
    return tuple(out)


def _build_server(
    name: str,
    block: dict,
    fallback: "ServerPolicy | None",
    top_default: str,
    source: str,
) -> ServerPolicy:
    _reject_unknown(block, _SERVER_KEYS, "servers.%s" % name, source)

    tools_raw = block.get("tools") or {}
    if not isinstance(tools_raw, dict):
        raise PolicyError("%s: servers.%s.tools must be a mapping" % (source, name))
    _reject_unknown(tools_raw, _TOOLS_KEYS, "servers.%s.tools" % name, source)

    if fallback is not None:
        base_allow = fallback.tools.allow
        base_deny = fallback.tools.deny
        base_action = fallback.tools.default
        base_rate = fallback.rate_limit
    else:
        base_allow = ()
        base_deny = ()
        base_action = top_default
        base_rate = None

    allow = _string_list(tools_raw.get("allow", base_allow), "servers.%s.tools.allow" % name, source)
    deny = _string_list(tools_raw.get("deny", base_deny), "servers.%s.tools.deny" % name, source)
    action = _action(tools_raw.get("default", block.get("default", base_action)), "servers.%s.default" % name, source)

    rate = _build_rate_limit(block.get("rate_limit", base_rate), "servers.%s.rate_limit" % name, source)
    return ServerPolicy(name=name, tools=ToolsRule(allow=allow, deny=deny, default=action), rate_limit=rate)


def _build_rate_limit(value: Any, label: str, source: str) -> RateLimit | None:
    if value is None:
        return None
    if isinstance(value, RateLimit):
        return value
    if isinstance(value, bool):
        raise PolicyError("%s: %s must be a mapping or an integer" % (source, label))
    if isinstance(value, int):
        if value <= 0:
            raise PolicyError("%s: %s must be greater than zero" % (source, label))
        return RateLimit(calls=value, per_seconds=60.0)
    if not isinstance(value, dict):
        raise PolicyError("%s: %s must be a mapping with calls and per_seconds" % (source, label))
    _reject_unknown(value, _RATE_KEYS, label, source)
    calls = value.get("calls")
    per_seconds = value.get("per_seconds", 60.0)
    if isinstance(calls, bool) or not isinstance(calls, int) or calls <= 0:
        raise PolicyError("%s: %s.calls must be a positive integer" % (source, label))
    if isinstance(per_seconds, bool) or not isinstance(per_seconds, (int, float)) or per_seconds <= 0:
        raise PolicyError("%s: %s.per_seconds must be a positive number" % (source, label))
    return RateLimit(calls=calls, per_seconds=float(per_seconds))


def _build_audit(value: Any, source: str) -> AuditConfig:
    if value is None:
        return AuditConfig()
    if isinstance(value, str):
        return AuditConfig(path=value)
    if not isinstance(value, dict):
        raise PolicyError("%s: audit must be a mapping or a path" % source)
    _reject_unknown(value, _AUDIT_KEYS, "audit", source)
    path = value.get("path")
    if path is not None and not isinstance(path, str):
        raise PolicyError("%s: audit.path must be a string" % source)
    include = value.get("include_arguments", True)
    if not isinstance(include, bool):
        raise PolicyError("%s: audit.include_arguments must be true or false" % source)
    return AuditConfig(path=path, include_arguments=include)


class RateLimiter:
    """Sliding window rate limiter with an injectable clock."""

    def __init__(self, limit: RateLimit, clock: Callable[[], float] = time.monotonic) -> None:
        self.limit = limit
        self._clock = clock
        self._events: deque[float] = deque()

    def acquire(self) -> tuple[bool, float]:
        now = self._clock()
        cutoff = now - self.limit.per_seconds
        while self._events and self._events[0] <= cutoff:
            self._events.popleft()
        if len(self._events) >= self.limit.calls:
            retry = self._events[0] + self.limit.per_seconds - now
            return False, max(retry, 0.0)
        self._events.append(now)
        return True, 0.0

    def reset(self) -> None:
        self._events.clear()


class Enforcer:
    """Applies policy decisions and per server rate limits."""

    def __init__(self, policy: Policy, clock: Callable[[], float] = time.monotonic) -> None:
        self.policy = policy
        self._clock = clock
        self._limiters: dict[str, RateLimiter] = {}

    def _limiter(self, server: str, limit: RateLimit) -> RateLimiter:
        limiter = self._limiters.get(server)
        if limiter is None or limiter.limit != limit:
            limiter = RateLimiter(limit, clock=self._clock)
            self._limiters[server] = limiter
        return limiter

    def check(self, server: str, tool: str) -> Decision:
        decision = self.policy.decide(server, tool)
        if not decision.allowed:
            return decision
        limit = self.policy.server(server).rate_limit
        if limit is None:
            return decision
        allowed, retry_after = self._limiter(server, limit).acquire()
        if allowed:
            return decision
        return Decision(
            False,
            "rate limit exceeded (%s)" % limit.describe(),
            "rate_limit",
            RATE_LIMITED_CODE,
            retry_after,
        )
