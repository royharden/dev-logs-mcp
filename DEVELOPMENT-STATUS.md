# Development status — 2026-10-15

**Local development resumed. Prototype under validation; no release acceptance.**
Native safety, dependency, evaluation and independent review gates remain open.
Existing proposals and metadata observations do not establish successful execution.

## Finished implementation

- Python 3.12 stdio MCP server using the pinned official SDK, five tool schemas and
  generated `tools.json`: list sources, tail, search, read range and grouped errors.
- Strict configuration and requests, configured-source lookup, parsed ISO/JSONL
  evidence with physical coordinates, redaction, RE2 matching, generation indexes,
  private cache support, authenticated cursors and bounded response serialization.
- Queue/concurrency controls and cooperative deadlines; error/refusal envelopes.
  Windows data access deliberately fails closed while safety guarantees are missing.
- Reusable core models, redaction, matcher, output/schema/style helpers and an
  injectable conformance runner. Application compatibility assertions now live in
  the application suite so the portable tests do not import the owning app.
- Canonical evaluation types and statistics integration, an incident scorer based
  on recorded responses, and three fixed public-input methods: scripted diagnosis,
  redacted search plus range, and naive paged range. These have toy controls only.
- Local-runtime/Bolt inspection handoff and template/description documentation.
  This application has no frontend, database, migrations or cloud services to provision.
- `scripts/demo.py --mode mock` generates plain/JSONL inputs and launches the actual
  CLI server, with all five tools, coordinate/redaction/bounds/append checks and
  unknown-source/outside-root refusals. Unsupported native access stays a failure.

## Verification completed, with scope limits

- Official SDK stdio controls exercised all five tools over a synthetic test catalog,
  including concurrency. This does not prove native log-file access.
- The configured-source demo ran on Windows: listing and both refusal checks worked;
  all eight plain/JSONL data calls returned `SOURCE_NOT_LOCAL` with zero source bytes.
  Its exit was 3 (`unsupported_required`), not normal-journey success. The new refusal
  regression and seven existing frame-guard checks passed. An initial demo validation
  error was fixed by validating strict transport enums in JSON mode; its failure is retained.
- The latest method/scorer toy set passed 54 checks. A separate detached pure-core
  and synthetic conformance set passed 148 checks with owner-app and MCP SDK imports
  blocked; three application compatibility checks passed separately. These sets
  overlap and must not be added into a whole-app result.
- Earlier full Windows testing has three unresolved metadata stability failures,
  pending POSIX checks and an unavailable required symlink fixture. A later narrow
  metadata diagnostic passed but did not explain or clear those earlier failures.
- Linux attempts ended before pytest produced a verdict. One timed out during
  startup; another rejected dependency contents. A read-only image/volume/port
  readiness observation completed, but it executed no application or native tests.
- The latest fresh Linux safety attempt stopped before container creation because
  the agent-ports check exceeded its command bound. No cache audit or POSIX test ran.
  Its own unused reservation was released after both exact container names were
  observed absent; the predecessor's retained cache remains untouched.
- Default pytest collection now includes the reusable mcpkit suite alongside the
  application suite. Collection coverage is separate from execution; known native
  failures remain required failures when those tests run.
- Application model calls are zero. No actual diagnosis-quality, 100 MB latency,
  offline-scanner, clean-wheel, remote-CI or finished-app acceptance result exists.

## Worked on / work in progress

- A receipt-aware Linux verifier is prepared. It separately validates the known
  installer receipt, includes every other file in the payload audit, and records
  observations before refusing a mismatch. It has synthetic controls, not a native run.
- Independent development and held-out synthetic fixtures were prepared separately.
  Their canonical controller metadata/provenance remains incomplete. Neither campaign
  has executed; private fixture material is not part of this repository.
- The scorer and methods need an actual controller binding source hashes, input
  normalization, implementation/configuration digests, captures and exposure history.
- Scanner package/interface research is complete enough to propose bounded setup;
  the scanner has not been installed or executed in the product workflow.
- Shared source has a detached portable-core check; native path, full application,
  complete consumer and downstream adoption evidence remain separate.

## Outstanding work

1. Explain the three Windows metadata failures and establish Windows data/no-recall
   guarantees before enabling data reads. No Linux-only acceptance exception is adopted.
2. Execute the five required POSIX path cases, native cache/catalog and full app checks
   under a fresh authorized resource allocation. Audit actual retained dependencies first.
3. Execute the implemented seeded demo successfully on a qualified Linux filesystem,
   including redaction and tail refresh. The retained Linux safety dependency list
   lacks MCP/RE2, so that cache alone cannot run the full configured-source workflow.
4. Complete controller metadata and freeze actual methods/configuration before any
   authorized development or held-out campaign. Preserve all misses/errors/abstentions.
5. Complete actual application-guard sabotage controls and the mandatory offline
   security scan; synthetic transport faults are not those application mutations.
6. Run the specified 100,000,000-byte plain/JSONL benchmarks with actual read, output,
   memory and latency observations. No performance values should be inferred from units.
7. Verify wheel installation, full detached consumption and CI. Standard test
   collection includes the shared-core suite; its native execution gates remain open.
8. Complete independent finished-app review and explicit release/platform dispositions.
   Publishing, remote creation/push, deployment and user client changes remain unperformed.

Keep supported behavior and unsupported-required capabilities distinct. A passing unit
subset, metadata check, copied source tree or API flag is not native or whole-app acceptance.

See [limitations](docs/LIMITATIONS.md), [evaluation design](docs/EVALUATION.md),
[runtime handoff](BOLT-HANDOFF.md) and [lessons learned](LESSONS.md).
