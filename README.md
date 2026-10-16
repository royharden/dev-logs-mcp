# Dev Logs MCP

A local stdio MCP server for bounded, redacted development-log inspection. It implements
`list_sources`, `tail`, `search`, `read_range`, and `errors` over explicitly configured sources.
The implementation is under validation. The Linux source-profile seeded demo and five
native SafePath cases have independent acceptance with notes for that exact capsule;
two further catalog/cache cases have author-only results. Windows data access fails
closed. Full conformance, evaluation, security and release gates remain open.

Local development resumed on 2026-10-15. [Development status](DEVELOPMENT-STATUS.md)
records completed work, work in progress and outstanding gates; [lessons](LESSONS.md)
records implementation and verification lessons. This is a local prototype under validation.

## Keyless quickstart

Python 3.12 and uv are required. From this repository:

```sh
uv sync --frozen
uv run dev-logs-mcp check-config fixtures/bootstrap.toml
uv run dev-logs-mcp export-tools --check tools.json
uv run python scripts/demo.py --mode mock
uv run pytest tests src/dev_logs_mcp/shared/mcpkit/tests
```

`check-config` checks TOML shape without opening configured log paths. The example paths
need not exist. Tool export also opens no log sources. No provider key is needed.
The demo generates temporary synthetic plain/JSONL logs and launches the actual CLI
server over stdio. It calls every tool and checks incident coordinates, stable
redaction, bounded responses, append refresh and unknown/outside-root refusals.
`mock` selects synthetic inputs; the catalog, filesystem policy and transport are real.
Windows currently reports `unsupported_required` and exits 3 because data reads
remain closed. This is a required normal-journey failure, even when the refusal
regression test passes. The seeded Linux demo passed on CPython 3.12.13, glibc 2.36,
x86-64 with generated logs on tmpfs. This is a bounded source-profile result;
other filesystems, Windows no-recall and complete platform acceptance remain unqualified.

## Example

Create a dedicated directory with synthetic logs and a TOML file using the shape in
`fixtures/bootstrap.toml`. Relative roots and source paths resolve beside the TOML file.
On a filesystem meeting the required native guarantees, the local invocation is:

```sh
uv run dev-logs-mcp serve /absolute/path/to/sources.toml
```

Connect an MCP stdio client to that command. Files above 6 MiB require a stable explicit
preflight using `index-source <config> <source_id> --cache-dir <private-cache-directory>`;
pass the same cache directory to `serve`. Use the seeded demo command above for
generated inputs; its platform failures are retained in the JSON report.
Explicit preparation has a separate 120-second cooperative budget shared across
two possible attempts; MCP calls and automatic small-file indexing remain limited
to five seconds. Exact-source large-input observations exist; full performance
qualification is pending.
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
establish native log access. A separate real configured-source Linux demo passed all
five tools with redaction, bounded results, append refresh and both refusal journeys;
five native SafePath cases were independently reproduced and accepted with notes.
Two catalog/cache cases passed separately without independent reproduction. The
Linux capsules use newline-converted Git-archive source, not the raw-Git wheel edition.
The earlier full Windows run's three metadata failures and unavailable
required symlink fixture remain unresolved; Linux results do not clear them.
The planned evaluation uses independently frozen, disjoint synthetic dev/heldout families
and grep/naive-range baselines. No remote CI or finished-app acceptance is claimed.
The complete current Linux application/shared-core suite has an author result of
592 passes and 17 named Windows-only skips, zero failures/errors, across exactly
609 collected/executed cases. This raw-Git source result awaits independent review;
it does not clear Windows failures or the remaining normative/performance/eval gates.
The incident scorer uses canonical evalkit records and controller-recorded response
references. Its toy controls cover evidence binding and fixed-denominator accounting;
corpus enrichment, actual campaign execution and controller provenance remain pending.

The optional [offline security scan](docs/SECURITY-SCAN.md) completed all five public
tool definitions with Cisco MCP Scanner 4.8.6 and reported 95 findings. Independent
review accepted the exact evidence and 24 narrow classifications with notes. All
95 findings and their residual risks remain visible; this is not a clean-security result.
Its isolated developer environment is separate from the application's dependencies.

## Cost

No model calls in this deterministic MVP. Runtime, storage and index costs are separate
and have bounded local observations in [the benchmark report](docs/BENCHMARK.md).
Deployment cost and performance qualification remain open. The reusable template
reserves canonical callledger integration.

## Limits

See [LIMITATIONS](docs/LIMITATIONS.md). Implemented ceilings include 8 MiB application
read budgets, a 32 KiB serialized response frame, 500 lines, and a cooperative five-second
whole-call deadline. Native all-path and performance verification remain open;
synchronous kernel calls cannot be preempted by the deadline.
Large continuously changing logs above 6 MiB may remain unavailable for the writer's
lifetime; strict invalidation prioritizes correct generation/line evidence.
The first exact 100 MB benchmark failed preparation before warm measurements;
that failure stays preserved. A separate exact-source run completed 600 warm calls
and four sweeps; see [benchmark scope](docs/BENCHMARK.md) for observed latencies,
repeated-read costs and missing process-I/O/configuration evidence.
Public package installation, publishing, and Bolt deployment remain pending owner actions.
See [BOLT-HANDOFF](BOLT-HANDOFF.md) for the local Python runtime boundary.

## Agent contribution

Coding agents authored the implementation and synthetic regression checks. Further
conformance/evaluation work and independent review are required before release.
