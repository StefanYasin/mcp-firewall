# mcp-firewall

A small policy gateway that sits between an MCP client and an MCP server over stdio. It checks every `tools/call` against a YAML policy, blocks what the policy denies, can rate limit a server, and writes one JSONL line per tool call with a summarized copy of the arguments.

I built this because handing an MCP server to an agent hands over that server's entire tool surface. Most of the time I want a narrow slice of it: read only tools, no deletes, a cap on calls per minute, and a record of what actually ran. This sits in the middle and does exactly that.

## How it works

- The client speaks newline delimited JSON-RPC on stdin and stdout, which is the MCP stdio transport.
- mcp-firewall starts the real server as a child process and forwards messages both ways, including notifications and server initiated requests.
- A `tools/call` is checked before it is forwarded. If the policy denies it, the client gets a JSON-RPC error with code `-32001` and the server never sees it. Rate limited calls get `-32002`.
- Every tool call, and every result that comes back, is appended to a JSONL audit log.

No runtime dependencies. The YAML parser is a small subset parser in `yaml_lite.py`, so there is nothing to install beyond Python 3.10 or newer.

## Install

```bash
git clone https://github.com/StefanYasin/mcp-firewall
cd mcp-firewall
pip install .
```

Or run it from a checkout without installing:

```bash
PYTHONPATH=src python -m mcp_firewall --config policy.example.yml --server "python examples/echo_server.py"
```

On Windows, use `set PYTHONPATH=src` in cmd or `$env:PYTHONPATH="src"` in PowerShell for that command.

## Quick start

```bash
mcp-firewall --config policy.yml --server "python my_mcp_server.py"
```

A policy that allows reads and blocks everything else:

```yaml
version: 1
default: deny

servers:
  filesystem:
    tools:
      allow: ["read_*", "list_*", "search_*"]
      deny: ["read_secrets"]
    rate_limit:
      calls: 30
      per_seconds: 60

audit:
  path: ./audit.jsonl
  include_arguments: true
```

Point an MCP client at the firewall instead of the server. The command is the firewall, and the real server goes in `--server`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-firewall",
      "args": [
        "--config", "/etc/mcp-firewall/policy.yml",
        "--name", "filesystem",
        "--server", "python /opt/mcp/filesystem_server.py"
      ]
    }
  }
}
```

`--name` picks the policy block. If you leave it out and the policy has exactly one server block, that block is used. Otherwise the `defaults` block applies.

## Policy

Rules are applied in this order:

1. A tool that matches `deny` is denied.
2. A tool that matches `allow` is allowed.
3. If `allow` is non-empty and nothing matched, the call is denied.
4. If `allow` is empty, `default` decides.

`default` can be `allow` or `deny` and defaults to `deny`. Tool names support shell style globs such as `read_*` and are matched case sensitively. `"*"` in `allow` means every tool that is not denied.

`defaults` is merged into every server block. A server block overrides only the keys it sets, so you can put shared deny rules in `defaults` and tune `allow` per server. An unknown server name falls back to `defaults` entirely.

Unknown keys are rejected, because a typo like `deney:` should fail at startup instead of quietly widening access.

`rate_limit` accepts either a mapping or a plain integer:

```yaml
rate_limit:
  calls: 30
  per_seconds: 60
```

```yaml
rate_limit: 120   # calls per 60 seconds
```

Only calls that pass the allow and deny rules count against the limit. A limited call returns an error with `data.retry_after_seconds` set.

### Policy file subset

The parser handles nested mappings, block sequences, flow sequences and mappings, quoted and plain scalars, comments, and `|` or `>` block scalars. It does not handle anchors, aliases, tags, or multiple documents, and it fails loudly if it meets one.

## CLI

```
mcp-firewall --config policy.yml --server "python server.py"
                 [--name NAME] [--audit PATH] [--no-arguments]
                 [--log-level debug|info|warning|error]

mcp-firewall --config policy.yml --check
mcp-firewall --config policy.yml --explain read_file
```

| flag | meaning |
| --- | --- |
| `--config`, `-c` | policy file, required |
| `--server`, `-s` | command that starts the MCP server on stdio |
| `--name`, `-n` | policy block to apply |
| `--audit` | override the audit log path |
| `--no-arguments` | keep tool arguments out of the audit log |
| `--check` | validate the policy and print the resolved rules as JSON |
| `--explain TOOL` | print the decision for one tool, exit 0 if allowed and 3 if denied |
| `--log-level` | stderr log level, default `warning` |

Nothing is ever logged to stdout, since that stream belongs to the protocol.

## Audit log

One JSON object per line. `tool_call` records are written before the call is forwarded or refused, so a denied call is logged even though the server never sees it. `tool_result` records are written when the response comes back.

```json
{"ts":"2026-05-04T12:00:00.123Z","event":"tool_call","server":"filesystem","tool":"read_file","request_id":7,"decision":"allow","reason":"tool matches allow rule 'read_file'","rule":"allow:read_file","arguments":{"path":"/tmp/notes.md"},"argument_keys":["path"],"argument_bytes":28}
{"ts":"2026-05-04T12:00:00.126Z","event":"tool_result","server":"filesystem","tool":"read_file","request_id":7,"duration_ms":3.412,"is_error":false,"result":"{\"content\":[{\"type\":\"text\",\"text\":\"hello\"}]}"}
```

Arguments are summarized before they are written:

- strings are clipped at 160 characters and end with a `...[N chars]` marker
- lists and mappings keep at most 8 items, with a `... N more items` marker
- nesting stops at 3 levels
- keys that look like secrets (`api_key`, `authorization`, `password`, `secret`, `token`, anything ending in `_key`, `_secret`, `_password`, `_token`) are replaced with `[redacted]`

`session_start`, `session_end`, `protocol_error`, and `invalid_tool_call` records cover the rest of the lifecycle. Tool calls without an `id` are forwarded but not counted as requests.

## Error codes

| code | meaning |
| --- | --- |
| `-32001` | denied by policy |
| `-32002` | rate limit exceeded |

Both carry `error.data` with `server`, `tool`, `rule`, and `reason`. Rate limited calls also carry `retry_after_seconds`.

## Tests

```bash
python -m pytest -q
```

The end to end tests start `tests/fake_server.py` as a real MCP server over stdio, put the gateway in front of it, and assert that allowed calls reach the server, denied calls never appear in the server's own trace, and the audit log holds both decisions with summarized arguments.

## Limits

- One server per gateway process. Run one gateway per server.
- Newline delimited JSON-RPC only, which is what the MCP stdio transport specifies. Content-Length framing is not implemented.
- JSON-RPC batch requests are refused with `-32600` instead of forwarded, since a batched `tools/call` would skip the policy check.
- `tools/list` is passed through, so a denied tool is still visible to the client. The call itself is blocked.
- Rate limit state is in memory and per process.
- No network listener, no persistent state, no authentication. It is a process boundary, not a sandbox.

## License

MIT

Built by [Stefan Yasin](https://stefanyasin.github.io/)
