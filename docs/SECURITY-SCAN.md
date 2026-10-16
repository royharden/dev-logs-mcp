# Offline static security scan

The pinned Cisco MCP Scanner 4.8.6 completed a keyless scan of the exact exported
five-tool specification at implementation commit
`eb137ed5e076bb1d507be76ee0a7ef5814e5135c`. Input SHA256:
`c56fa493b3cb2c3c4cfcb1d0be78fba4b626aa4bb5f4d30a959d27e9c6f3112d`.
This scans public definitions, not live servers, logs, dependencies for CVEs, or models.

Actual coverage: YARA 10/10 description/parameter analyses, readiness 5/5 complete
definitions, prompt-defense 5/5 descriptions, zero analyzer errors and ten packaged
YARA rule files. Positive controls produced 1/8/12 findings respectively. A deliberately
raising analyzer was caught by the completion guard despite the vendor's completed
labels. The wrapper requires actual completion counts, not just process success.

The run produced **95 findings**: 2 YARA, 40 readiness and 53 prompt-defense.
Scanner exit 1 means completed with findings requiring disposition; exit 2 means
incomplete. No clean-security or release acceptance follows from completion.
The following author assessments are **proposed and awaiting independent review**;
every raw finding remains retained. No rule was disabled or description padded to
produce a better heuristic score.

| Disposition | Findings | Proposed assessment and remaining boundary |
| --- | ---: | --- |
| SCN-YARA-001 | 2 | `credential_harvesting` parameters findings on tail/search. The rule combines the `private_key` omission-reason enum in outputSchema with the tool names as file-operation words. These are not credential values or requested credential files. Proposed lexical false positives; review remains required. |
| SCN-READY-001 | 5 | No ad-hoc timeout field. Runtime has a cooperative five-second budget including queue time; synchronous kernel calls remain non-preemptible and full native deadline proof remains open. |
| SCN-READY-003 | 5 | No maxRetries schema field. No provider/network retry loop exists; explicit generation preparation retries at most twice. |
| SCN-READY-006 | 5 | Error schema already exists in outputSchema's ToolError union. The heuristic expects a separate errorSchema field. |
| SCN-READY-010 | 1 | `all` refers to the all-path read budget; tail is still one configured source and at most 500 lines. |
| SCN-READY-012 | 1 | errors.cursor and errors.since have length constraints inside anyOf unions; semantic validation remains runtime code. |
| SCN-READY-013 | 5 | Four active calls, queue of 16 and BUSY expiry bound overload. No requests-per-second limiter is claimed; stress/native conformance remains open. |
| SCN-READY-014 | 5 | Server version 0.1.0 and envelope schema_version 1 exist; no separate per-tool version field. |
| SCN-READY-015 | 5 | Coverage/error/truncation fields exist. Dedicated metrics/tracing hooks and whole-process I/O/performance proof are not claimed. |
| SCN-READY-017 | 5 | MCP annotations already declare read-only, non-destructive and idempotent hints. They are not top-level idempotent fields or enforcement by themselves. |
| SCN-READY-018 | 2 | The `rm ` substring occurs inside `platform ` safety prose. The tools accept no command or shell operation. Proposed substring false positives. |
| SCN-READY-020 | 1 | Describing search by name does not create a recursive tool/agent loop. |
| SCN-PD-ABUSE_PREVENTION | 5 | Programmatic per-call/queue limits exist; frequency limiting and full stress evidence remain separate. |
| SCN-PD-CONTEXT_OVERFLOW | 5 | Frame/line/input bounds exist; these do not qualify an external model's context policy. |
| SCN-PD-DATA_LEAKAGE | 5 | Configured roots and redaction/whole-line omission exist. Unknown secret shapes and full secret-family conformance remain residual risks. |
| SCN-PD-INDIRECT_INJECTION | 5 | Log text carries untrusted-data markers. An external coding agent may still misinterpret it; no empirical prompt-injection immunity is claimed. |
| SCN-PD-INPUT_VALIDATION | 4 | Strict schemas and semantic validators exist. Description keyword matching is not the validation boundary. |
| SCN-PD-INSTRUCTION_OVERRIDE | 2 | No model follows instructions inside this server; external caller instruction hierarchy still needs its own controls. |
| SCN-PD-MULTILANG_BYPASS | 5 | Unicode evidence is preserved; external multilingual prompt robustness is unmeasured. |
| SCN-PD-OUTPUT_MANIPULATION | 5 | Strict envelopes and consistent structured/text channels exist. Untrusted prose remains unsafe to obey as instructions. |
| SCN-PD-OUTPUT_WEAPONIZATION | 5 | Tools may return harmful-looking log evidence but execute no actions. Consumer interpretation remains a residual risk. |
| SCN-PD-ROLE_ESCAPE | 5 | No server model role exists; external-agent role escape is not qualified by this scan. |
| SCN-PD-SOCIAL_ENGINEERING | 5 | Natural-language content cannot expand deterministic source authority. Social engineering of the caller remains unmeasured. |
| SCN-PD-UNICODE_ATTACK | 2 | Source IDs are ASCII-allowlisted; log text preserves Unicode. Confusable secrets and caller interpretation remain incompletely qualified. |

## Reproducing the optional developer check

The ordinary application environment remains lean. The separate
`requirements/security-linux-py312.txt` pins the complete optional binary-wheel
scanner tuple for CPython 3.12/Linux x86-64 with glibc 2.28 or newer. Install it in
an isolated environment outside the product checkout:

```sh
python3.12 -m venv /absolute/path/to/scanner-venv
/absolute/path/to/scanner-venv/bin/python -m pip install --require-hashes -r requirements/security-linux-py312.txt
/absolute/path/to/scanner-venv/bin/python scripts/security_scan.py --output /absolute/path/to/new-security-report.json
```

The qualified run used CPython 3.12.13/glibc 2.36/x86-64, a fresh offline environment,
102 exact resolved wheels, an unprivileged read-only container with networking
disabled, and no credentials or personal logs. All installed versions matched the
complete resolved dependency/extra closure; pip check passed. Model-related libraries
were imported during official package initialization, but no LLM/API analyzer or
model/provider method was used. The Python audit guard recorded zero prohibited
operations. The container exited normally, was removed, and its claim was released.

The CLI disables dotenv loading and remote model-cost metadata, then installs a
Python audit guard before vendor imports. That guard is not a whole-OS sandbox;
use an OS network boundary and empty credentials/home for qualification. Readiness
OPA and LLM judges remain disabled. Public tool definitions only belong in this input.

An earlier run installed the packages but failed its installed-name verifier because
it omitted dotted-name normalization (`boolean.py` versus `boolean-py`). It never
initialized the scanner. A corrected, separately authorized fresh run used complete
project-name normalization and rejected missing, wrong-version or duplicate metadata.
Earlier failures remain failures; the later result does not rewrite them.

Static findings and their dispositions do not replace application guard sabotage,
Windows no-recall, complete conformance, benchmarks, independent evaluation or final
review. See [development status](../DEVELOPMENT-STATUS.md) and
[limitations](LIMITATIONS.md). Vendor: [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner),
Apache-2.0; package license files remain in the separate tool environment.

## Separate application safeguard controls

Four later native Linux controls execute the actual SourceCatalog/LogEngine,
redactor and renderer against generated allowlisted files. Each baseline passes;
the unchanged conformance oracle detects each test-only mutation:

| Mutated guard | Observed rejection |
| --- | --- |
| Unknown-ID lookup redirected to a configured source | `unexpected_status`; baseline reads 0 bytes, mutation reads 7872 |
| Default secret detectors disabled | `private_marker_leaked`; both read 128 bytes |
| Renderer cap raised from 32768 to 65536 bytes | `frame_limit`; baseline frame 25909 bytes, mutation 50425 |
| Remaining-byte guard disabled for a 4096-byte call budget | `read_limit`; baseline reads 0 bytes, mutation reads 7872 |

These four checks passed in 2.17s inside the fresh offline job. The job's 54 source
files exactly match raw Git at `50b77f8fdeaf1520b066c40949aa8d4065aeae05`.
They use adapter serialization, not captured SDK stdio. They do not sabotage
outside-root containment or prove whole-process/global 8 MiB bounds. No production
guard was relaxed. Independent review is pending; the scanner's original source
tuple and its 95 findings remain unchanged.
