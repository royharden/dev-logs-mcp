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
Independent review accepted the exact static evidence and the following 24 narrow
classifications with notes. **All 95 findings remain addressable, including 32 HIGH
and both credential HIGH findings.** No automatic waiver or clean-security verdict
was issued. F020/F040 are lexical omission-enum false positives in this exact input;
that classification does not establish safe credential handling generally.

No rule was disabled or description padded to improve a heuristic score.

| Group / finding IDs | Narrow independent classification | Retained boundary |
| --- | --- | --- |
| SCN-READY-001: F001, F021, F041, F061, F077 | source-control-supported; hard-deadline residual retained | Synchronous OS calls are not preempted by the cooperative checks. Native hard-deadline and complete process performance qualification remains open. |
| SCN-READY-003: F002, F022, F042, F062, F078 | metadata warning disposition supported; bounded retry source verified | Static bounded-loop inspection is not independent execution of source-change or deadline controls in this review. |
| SCN-READY-006: F003, F023, F043, F063, F079 | schema-detector mismatch supported | Schema presence alone does not prove every runtime exception is sanitized or every SDK transport serializes it correctly. |
| SCN-READY-013: F004, F025, F044, F064, F081 | retain actual absence of frequency limiter; bounded overload mitigation supported | Request-frequency control and native sustained stress/resource qualification remain unverified. INT must decide suitability for the local stdio deployment; do not relabel this as a false positive for all deployments. |
| SCN-READY-014: F005, F026, F045, F065, F082 | metadata scope mismatch supported | Compatibility and migration behavior across versions were not executed here; no new duplicate per-tool version authority is warranted merely to silence a heuristic. |
| SCN-READY-015: F006, F027, F046, F066, F083 | retain observability gap with existing response evidence | Dedicated operational metrics/tracing and whole-process I/O/latency observations remain absent or unqualified. Tool byte counters are not complete process telemetry. |
| SCN-READY-017: F007, F028, F047, F067, F084 | lexical/annotation mismatch supported; no identical-result guarantee | Hints are descriptive rather than access-control enforcement. A changing log generation can change a repeated read result; this is not a promise of identical responses or no internal caching. |
| SCN-READY-018: F008, F029 | narrow lexical false positive supported | This disposes these two specific keyword witnesses only; it does not certify all process boundaries or arbitrary caller behavior. |
| SCN-PD-DATA_LEAKAGE: F009, F030, F050, F068, F086 | retain secrecy/conformance residual; existing source controls supported | Unknown secret formats, confusables, configured custom rules and complete secret-family conformance remain unqualified; no universal redaction or private-data safety claim. |
| SCN-PD-ROLE_ESCAPE: F010, F031, F051, F069, F087 | retain external-consumer risk; deterministic server boundary supported | An external coding agent may follow malicious log prose or abandon its role. No caller model, prompt hierarchy or empirical role robustness was tested. |
| SCN-PD-INDIRECT_INJECTION: F011, F032, F052, F070, F088 | retain external-consumer risk; untrusted labeling supported | Labeling is not a reliable defense if an external agent treats returned prose as instructions. No empirical indirect-injection immunity is established. |
| SCN-PD-OUTPUT_WEAPONIZATION: F012, F033, F053, F071, F089 | retain downstream content risk | Consumer action selection and harmful-content interpretation require separate controls; harmful-looking evidence is not made safe merely by being read-only. |
| SCN-PD-OUTPUT_MANIPULATION: F013, F034, F054, F072, F090 | existing serialization control supported; consumer risk retained | No fresh wire/SDK run was performed, and valid untrusted text can still manipulate an external model's interpretation. |
| SCN-PD-MULTILANG_BYPASS: F014, F035, F055, F073, F091 | retain unmeasured multilingual consumer risk | External agent multilingual prompt robustness and secret detection across languages were not measured or waived. |
| SCN-PD-UNICODE_ATTACK: F015, F056 | partial validation supported; confusable/caller risk retained | Confusable secrets, invisible text and caller interpretation are not comprehensively detected or qualified. |
| SCN-PD-CONTEXT_OVERFLOW: F016, F036, F057, F074, F092 | existing byte/line limits supported; downstream context residual retained | Bounds do not prove a caller's model context-window policy or complete native memory/latency behavior. No fresh transport/stress execution occurred. |
| SCN-PD-SOCIAL_ENGINEERING: F017, F037, F058, F075, F093 | retain unmeasured caller risk | The external caller may still be socially engineered; no user/model persuasion study or role/hierarchy evidence is available in this scope. |
| SCN-PD-INPUT_VALIDATION: F018, F038, F059, F094 | description detector mismatch supported by typed boundary | No fresh validator runtime/fuzzing was performed; static schema presence is not universal validation correctness. |
| SCN-PD-ABUSE_PREVENTION: F019, F039, F060, F076, F095 | retain frequency/stress residual; concurrency/per-call mitigation supported | Sustained abuse, process-resource stress and remote/multi-tenant suitability require separate qualification and INT scope decision. |
| SCN-YARA-001: F020, F040 | two narrow credential lexical false positives supported | This disposes F020 and F040 only. Real log secrecy and unknown secret-family conformance remain open under SCN-PD-DATA_LEAKAGE. No general YARA quality or credential-handling security acceptance. |
| SCN-READY-010: F024 | narrow scope-overload lexical false positive supported | Whole-process reads and OS-call performance remain separate from the logical per-call byte budget. |
| SCN-READY-020: F048 | natural-name lexical false positive supported | An external agent's repeated invocation policy is not controlled or qualified by this server's deterministic dispatcher. |
| SCN-PD-INSTRUCTION_OVERRIDE: F049, F085 | retain external instruction-hierarchy risk | Caller system/developer hierarchy and untrusted-content behavior must be tested separately; no model instruction-override guarantee or waiver. |
| SCN-READY-012: F080 | nested-union schema detector mismatch supported | Cursor authenticity/currentness and semantic runtime negatives were not rerun in this scanner evidence review. |

Application implementers retain native hard-deadline/preemption, process I/O/memory/
latency/stress, complete secret-family/confusable/custom-rule conformance, operational
observability and applicable request-frequency work. Deployment owners must assess
admission and deployment-specific controls. Caller owners retain external model
instruction hierarchy, indirect injection, multilingual/social/output/context risks.
The accepted scanner evidence does not transfer those responsibilities or approve
remote/multitenant deployment. The four application-control checks below remain a
separate review scope.

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
guard was relaxed. Independent reproduction and acceptance with notes cover those
exact four controls, retaining the boundaries above. The scanner's original source
tuple and all 95 findings remain unchanged. Later preparation timing and benchmark
changes have their own source and review scope.
