"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from . import __version__, yaml_lite
from .audit import AuditLog
from .policy import Enforcer, Policy, PolicyError
from .proxy import Gateway

DEFAULT_AUDIT_PATH = "mcp-firewall-audit.jsonl"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-firewall",
        description="Policy gateway and audit log for an MCP server over stdio.",
    )
    parser.add_argument("--config", "-c", help="path to the YAML policy file")
    parser.add_argument("--server", "-s", help="command that starts the MCP server on stdio")
    parser.add_argument("--name", "-n", help="policy block to apply (defaults to the only one)")
    parser.add_argument("--audit", help="override the audit log path")
    parser.add_argument(
        "--no-arguments",
        action="store_true",
        help="do not write tool arguments to the audit log",
    )
    parser.add_argument(
        "--log-level",
        default="warning",
        choices=["debug", "info", "warning", "error"],
        help="stderr log level (default: warning)",
    )
    parser.add_argument("--explain", metavar="TOOL", help="print the decision for TOOL and exit")
    parser.add_argument("--check", action="store_true", help="validate the policy and print a summary")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="mcp-firewall %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    if not args.config:
        parser.error("--config is required")

    try:
        policy = Policy.load(args.config)
    except (PolicyError, yaml_lite.YamlError, OSError) as exc:
        print("mcp-firewall: %s" % exc, file=sys.stderr)
        return 2

    name = args.name or policy.default_server_name()

    if args.check:
        print(json.dumps(policy.summary(selected=name), indent=2, sort_keys=True))
        return 0

    if args.explain:
        decision = policy.decide(name, args.explain)
        print(
            json.dumps(
                {
                    "server": name,
                    "tool": args.explain,
                    "policy": policy.source,
                    "decision": decision.as_dict(),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if decision.allowed else 3

    if not args.server:
        parser.error("--server is required unless --check or --explain is used")

    audit_path = args.audit or policy.audit.path or DEFAULT_AUDIT_PATH
    include_arguments = policy.audit.include_arguments and not args.no_arguments
    try:
        audit = AuditLog(audit_path, include_arguments=include_arguments)
    except OSError as exc:
        print("mcp-firewall: cannot open audit log %s: %s" % (audit_path, exc), file=sys.stderr)
        return 2

    enforcer = Enforcer(policy)
    gateway = Gateway(
        enforcer,
        audit,
        args.server,
        server_name=name,
        policy_source=policy.source,
    )
    logging.getLogger("mcp_firewall").info(
        "policy %s, server block %r, audit %s", policy.source, name, audit_path
    )
    try:
        return gateway.run()
    except (OSError, ValueError) as exc:
        print("mcp-firewall: %s" % exc, file=sys.stderr)
        audit.emit("session_error", server=name, error=str(exc))
        audit.close()
        return 1
