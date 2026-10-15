# Dev Logs MCP

A local stdio MCP server for bounded, redacted development-log inspection. It implements
`list_sources`, `tail`, `search`, `read_range`, and `errors` over explicitly configured sources.
The implementation is under validation. Windows data access fails closed; Linux native
verification, evaluation, security scanning, packaging, and independent review remain pending.

## Keyless quickstart

Python 3.12 and uv are required. From this repository:

```sh
uv sync --frozen
uv run dev-logs-mcp check-config fixtures/bootstrap.toml
uv run dev-logs-mcp export-tools --check tools.json
uv run pytest tests src/dev_logs_mcp/shared/mcpkit/tests
```

`check-config` checks TOML shape without opening configured log paths. The example paths
need not exist. Tool export also opens no log sources. No provider key is needed.

## Example

Create a dedicated directory with synthetic logs and a TOML file using the shape in
`fixtures/bootstrap.toml`. Relative roots and source paths resolve beside the TOML file.
Once native Linux validation is complete, the local invocation is:

```sh
uv run dev-logs-mcp serve /absolute/path/to/sources.toml
```

Connect an MCP stdio client to that command. Files above 6 MiB require a stable explicit
preflight using `index-source <config> <source_id> --cache-dir <private-cache-directory>`;
pass the same cache directory to `serve`. The seeded diagnosis demo is still pending.
Do not use personal or customer logs for development tests.

## Architecture

Strict configuration and arguments feed a configured-source catalog, opened-handle path
authorization, generation index, bounded reader, parser, redactor, and query engine.
The official MCP SDK supplies stdio transport. Matching sees redacted text only.
`src/dev_logs_mcp/shared/mcpkit` contains reusable path, redaction, matcher, schema, error,
and output-budget primitives. Its detached consumer/conformance verification is pending.

## Results

Product conformance, diagnosis and latency: **not established**. Unit and SDK stdio controls
have run locally, including all five tools over a test catalog. Those controls do not
establish native log access. The latest full Windows run has three metadata stability
failures, seven pending POSIX checks, and an unavailable required symlink fixture.
The planned evaluation uses independently frozen, disjoint synthetic dev/heldout families
and grep/naive-range baselines. No remote CI or finished-app acceptance is claimed.

## Cost

No model calls in this deterministic MVP. Runtime, storage and index costs are separate
and not yet benchmarked. The reusable template reserves canonical callledger integration.

## Limits

See [LIMITATIONS](docs/LIMITATIONS.md). Implemented ceilings include 8 MiB application
read budgets, a 32 KiB serialized response frame, 500 lines, and a cooperative five-second
whole-call deadline. Native all-path and performance verification remain open;
synchronous kernel calls cannot be preempted by the deadline.
Large continuously changing logs above 6 MiB may remain unavailable for the writer's
lifetime; strict invalidation prioritizes correct generation/line evidence.
Public package installation, publishing, and Bolt deployment remain pending owner actions.
See [BOLT-HANDOFF](BOLT-HANDOFF.md) for the local Python runtime boundary.

## Agent contribution

Coding agents authored the implementation and synthetic regression checks. Further
conformance/evaluation work and independent review are required before release.
