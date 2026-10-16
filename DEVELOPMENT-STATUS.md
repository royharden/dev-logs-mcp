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
- An earlier fresh Linux safety attempt stopped before container creation because
  the agent-ports check exceeded its command bound. No cache audit or POSIX test ran.
  Its own unused reservation was released after both exact container names were
  observed absent; the predecessor's retained cache remains untouched.
- Subsequent fresh Linux attempts acquired exact locked public wheels and used
  isolated offline environments. One stopped at native-extension mapping; its
  effective mount flags were not recorded. A corrected executable dependency mount
  progressed, then an author dependency collector omitted pyjwt[crypto]. Neither
  attempt reached native tests or the demo, and both were removed/released.
- The corrected closure propagates extras, checks actual wheel Requires-Dist and
  versions, and passes three focused collector controls. It contains 34 Linux
  archives, 12,017,147 bytes, with exact committed lock URLs/sizes/SHA256 and license
  metadata. The original 31 archives were reused; only the missing three were acquired.
- At implementation commit `b05f38e2f1b79b713133ecae3f0c0d7d468d661f`, five actual
  POSIX SafePath cases passed, followed by the real configured CLI stdio demo:
  12 calls, 11 successes and UNKNOWN_SOURCE refusal, all five tools, generated
  plain/JSONL logs, stable redaction, physical coordinates, bounded results,
  append/generation refresh and outside-root CONFIG_INVALID. A separate run passed
  two native catalog/cache cases, including privacy-mode and hard-link rejection.
  Both used CPython3.12.13/glibc2.36/x86-64, fresh offline source-profile environments
  and tmpfs fixture data; independent review is pending. No other filesystem/Windows
  or detached-wheel normal result is implied. Owned containers were removed and
  ledger claims released. A copied supervisor normal-status field in the two-case
  supplement is not a new demo result; its worker correctly records no demo rerun.
- A disjoint source synthetic parser/query/generation/cache/window slice passed 121
  cases; one native case was deselected. This is neither a full suite nor detached proof.
- Exact local packaging verification exists in two distinct editions at that same
  implementation commit. The original working-byte wheel, SHA256
  `a820eb6e4bfc214a361d41fa31411c542a56ff67420917d7b55b87a7a183a439`,
  has 56 entries; all 50 source files match its working/installed edition, but only
  45 match raw Git (five differ only by CRLF/LF). Independent disposition accepted
  that exact wheel/installed metadata subset with notes; it did not accept the app.
  The new raw-Git wheel, SHA256
  `1f940fa72d9f03d6b70a1d60a38e1d32c35bce4ce61603fde6e07c98639fa183`,
  has 56 entries, all 50 source files and both root notices matching raw Git. Two
  independent backend processes with the same source/toolchain/epoch produced
  identical hashes. A fresh offline install passed imports and version/config/catalog
  checks; independent disposition is pending. This is same-toolchain repeatability,
  not cross-platform reproducibility. The earlier Windows dependency cache proves
  RECORD-qualified copied members, not original upstream ZIP authenticity. Its old
  runtime contains existing bytecode; source-forced checks preserved that inventory.
  The fresh raw-Git runtime's app bytecode inventory was empty before/after checks.
- Default pytest collection now includes the reusable mcpkit suite alongside the
  application suite. Collection coverage is separate from execution; known native
  failures remain required failures when those tests run.
- Application model calls are zero. No actual diagnosis-quality, 100 MB latency,
  offline-scanner, full detached core/runtime, remote-CI or finished-app acceptance
  result exists. Later documentation changes do not relabel the frozen runtime tuple.

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
2. Obtain independent review of the seven executed POSIX path/cache/catalog cases
   and run full application/conformance checks with exact dependency/source binding.
3. Obtain independent review of the successful seeded Linux source-profile demo,
   then extend actual configured-source and detached-runtime coverage. The old retained
   safety cache still lacks MCP/RE2; the successful run used a separate fresh tuple.
4. Complete controller metadata and freeze actual methods/configuration before any
   authorized development or held-out campaign. Preserve all misses/errors/abstentions.
5. Complete actual application-guard sabotage controls and the mandatory offline
   security scan; synthetic transport faults are not those application mutations.
6. Run the specified 100,000,000-byte plain/JSONL benchmarks with actual read, output,
   memory and latency observations. No performance values should be inferred from units.
7. Complete full detached consumption and CI beyond the exact local packaging subset. Standard test
   collection includes the shared-core suite; its native execution gates remain open.
8. Complete independent finished-app review and explicit release/platform dispositions.
   Publishing, remote creation/push, deployment and user client changes remain unperformed.

Keep supported behavior and unsupported-required capabilities distinct. A passing unit
subset, metadata check, copied source tree or API flag is not native or whole-app acceptance.

See [limitations](docs/LIMITATIONS.md), [evaluation design](docs/EVALUATION.md),
[runtime handoff](BOLT-HANDOFF.md) and [lessons learned](LESSONS.md).
