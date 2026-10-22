from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

POLICY = """
version: 1
default: deny
servers:
  fake:
    tools:
      allow: ["echo", "read_*"]
      deny: ["read_secrets"]
"""


def run_cli(tmp_path, *args, policy_text=POLICY, write_policy=True):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    command = [sys.executable, "-m", "mcp_firewall"]
    if write_policy:
        path = Path(tmp_path) / "policy.yml"
        path.write_text(policy_text, encoding="utf-8")
        command += ["--config", str(path)]
    command += list(args)
    return subprocess.run(command, capture_output=True, text=True, timeout=60, env=env)


def test_check_prints_the_resolved_policy(tmp_path):
    result = run_cli(tmp_path, "--check")
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["servers"]["fake"]["allow"] == ["echo", "read_*"]
    assert summary["effective"]["deny"] == ["read_secrets"]
    assert summary["selected_server"] == "fake"


def test_explain_exit_codes(tmp_path):
    allowed = run_cli(tmp_path, "--explain", "read_file")
    assert allowed.returncode == 0
    assert json.loads(allowed.stdout)["decision"]["allowed"] is True

    denied = run_cli(tmp_path, "--explain", "read_secrets")
    assert denied.returncode == 3
    decision = json.loads(denied.stdout)["decision"]
    assert decision["allowed"] is False
    assert decision["code"] == -32001


def test_version(tmp_path):
    result = run_cli(tmp_path, "--version", write_policy=False)
    assert result.returncode == 0
    assert "0.1.0" in result.stdout


def test_broken_policy_exits_two(tmp_path):
    result = run_cli(tmp_path, "--check", policy_text="default: nope\n")
    assert result.returncode == 2
    assert "allow" in result.stderr


def test_missing_config_exits_two(tmp_path):
    result = run_cli(tmp_path, "--check", write_policy=False)
    assert result.returncode == 2
    assert "--config is required" in result.stderr
