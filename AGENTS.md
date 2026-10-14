# Product instructions — version 1

This inner directory is the product Git root. The parent shell owns agent plans,
receipts, registries, private research and chat exports. Keep all of those outside
this repository; use the explicit outer registry when enrolled from this directory.
Do not initialize another registry or copy credentials here.

Commands: `uv sync --frozen`, `uv run ruff check .`, `uv run ruff format --check .`,
`uv run pytest`, `uv run dev-logs-mcp check-config fixtures/bootstrap.toml`.
The runtime is Python 3.12. Keep the committed uv lock consistent.

Current state: W01 contracts/configuration bootstrap only. No log-reading MCP server,
path authorization, redactor, pagination, conformance suite or evaluation is complete.
Never describe schema validation as filesystem authorization or a full-frame bound.
Later implementation must enforce the approved caps on actual reads/wire output.

Five tools only: list_sources, tail, search, read_range, errors. Sources come from
explicit configuration, never request paths. Read-only logs, redaction before search,
exact generation-bound line evidence and untrusted-data markers are invariants.
No model, shell/process-control tool, listener or hydration opt-in in the MVP.
FRESHNESS-1: changing sources larger than 6 MiB may be unavailable until stable preflight.

Only synthetic/licensed fixtures and value-free labels; generate synthetic secret
shapes into ignored fixtures/generated. Never commit customer/personal logs, real
credentials, environment files, transcripts or user-machine index caches.

Use session-provided canonical memory/sync skills; no skill content or mirrors are
vendored into this product. Keep this file the shared product instruction source.
CLAUDE.md and the Cursor rule point here; Grok and Codex read AGENTS.md directly.
One owner changes shared schemas/config/lock/integration. Consumer contracts and
vendored commits require actual owning-app coordination and provenance.

Change log: version 1 establishes W01 commands, scope and outer-shell boundary.
