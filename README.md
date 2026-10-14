# Dev Logs MCP

A planned local stdio MCP server for bounded, redacted development-log inspection.
Current release is the W01 contract/configuration bootstrap; log-reading tools are not implemented.

## Keyless quickstart

Python 3.12 and uv are required. From this repository:

```sh
uv sync --frozen
uv run dev-logs-mcp check-config fixtures/bootstrap.toml
uv run pytest
```

The command checks configuration shape without opening the configured log paths.
It does not authorize those paths or establish log-reading safety. No provider key is needed.

## Example

The bootstrap config describes one synthetic source. The command reports that the
shape is valid and the source paths were neither authorized nor read. The later seeded
diagnosis demo will exercise list/errors/search/range and append/tail over real stdio.

## Architecture

`contracts.py` defines strict requests/results and approved hard ceilings; `config.py`
validates TOML shape; `cli.py` provides the configuration check. Filesystem authorization,
redaction, generation indexes, MCP dispatch and standalone mcpkit exports are later work.

## Results

Product conformance, diagnosis and latency: **not yet measured**. The planned evaluation
uses fixed disjoint synthetic dev/held-out families and grep/naive-dump baselines.
Bootstrap unit checks do not establish product acceptance or remote CI execution.

## Cost

No model calls in this deterministic MVP. Runtime, storage and index costs are separate
and not yet measured. The reusable template reserves S3's canonical callledger integration.

## Limits

See [LIMITATIONS](docs/LIMITATIONS.md). Intended MVP caps are 8 MiB all-path reads,
32 KiB complete response frame, 500 lines and a five-second whole-call deadline;
schema constants alone do not enforce I/O, timing or wire-size limits.
Large continuously changing logs above 6 MiB may remain unavailable for the writer's
lifetime; strict invalidation prioritizes correct generation/line evidence.
Public package installation, publishing and Bolt deployment are not available claims.

## Agent contribution

Coding agents authored this bootstrap. The repository tests and receipts identify
what actually ran; the complete application needs further implementation and independent review.
