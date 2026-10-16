# Lessons learned

- Test the same conformance oracle before and after a real application guard mutation.
  Fabricated unsafe frames only test the checker. Retain native handle observations
  separately from application counters and distinguish renderer serialization from
  captured stdio; a reduced-budget control does not qualify the global read ceiling.
- A vendor coordinator can catch analyzer errors and still label a scan complete.
  Count actual analyzer attempts/completions/errors and run positive and raising
  controls. Preserve all findings for named disposition instead of adjusting prose
  or disabling rules to improve a heuristic score.
- Normalize Python distribution identities using the complete PEP 503 rule, including
  dots. Compare the full resolved extras closure to actual installed metadata and
  reject duplicates; base pip check alone does not prove requested extras were installed.
- Full scanner initialization may import model-related libraries even in keyless mode.
  Review the pinned import path, disable dotenv/remote metadata, enforce OS isolation,
  and distinguish imports from actual model/provider calls. Keep optional scanner
  dependencies separate from the lean application environment.
- Git archive can convert every source file's newlines. Verify capsule bytes against
  raw Git and retain the edition difference even when behavior checks pass; never
  silently transfer a source-capsule result to a separately built raw-Git wheel.
- Validate strict structured transport models in JSON mode when enum values arrive
  as strings. Python-object validation can reject a valid wire response. Preserve
  the failing attempt and test error envelopes as well as successful payloads.
- A demo must return a required-failure status when native reads are unavailable.
  A passing test of the refusal is separate from successful normal use.
- Propagate transitive dependency extras when deriving an offline closure. MCP's
  pyjwt[crypto] edge requires cryptography even if a base-only pip check passes.
  Audit actual wheel Requires-Dist entries and requested extras against the lock.
- Native extensions need an executable dependency filesystem. Record effective
  mount flags before importing; fixture mounts can remain noexec. A shared-object
  mapping failure without those observations does not retrospectively prove a cause.
- Preserve SystemRoot through explicit-key environment lookup on Windows. Iterating
  environment keys and filtering with mixed-case literals can drop SYSTEMROOT and
  break stdlib socket imports; this does not explain separate native no-recall failures.
- Compare built source bytes to raw Git blobs when claiming a Git-source edition.
  Working-copy CRLF conversion can produce a different, internally consistent wheel.
  Bind claims to the exact wheel hash and separate same-toolchain repeatability from
  cross-platform reproducibility. Source-forced runtime checks need explicit cache policy.
- Define dependency inventory boundaries before hashing. A payload hash captured
  before writing an installer receipt does not describe the final directory. Verify
  the exact receipt separately; never ignore arbitrary or nested metadata files.
- Await command completion before checking a copied snapshot or editing tested code.
  Preserve failed attempts and their original bytes; a later success does not rewrite
  the scope or outcome of an earlier run.
- Keep application compatibility assertions outside portable-core tests. Validate
  detached imports with both the owning application and optional SDK blocked.
- Use the supported JUnit family when recording per-test properties. Report portable,
  synthetic, native, unsupported-required and not-applicable scopes independently.
- Metadata probes, API flags and dependency setup are not data-authorization or
  no-recall proof. Keep unsupported data paths closed. A failed CloudFiles experiment
  does not establish a cause or prove that Windows support is impossible.
- Record actual process/resource terminal state and absence. A CLI timeout or exit is
  not a container verdict; metadata readiness is not test execution. Preserve owned
  retained resources and avoid unrelated cleanup.
- A JSON object starts a new event even when its timestamp is invalid. Do not inherit
  the previous record's timestamp or severity; retain independently valid severity.
- Apply redaction before matching and return whole omission markers on uncertainty.
  Bound the complete serialized response, including duplicate text/structured channels.
  Metadata helpers must not introduce uncounted file-body reads.
- Ground incident scoring in actual recorded response references, frozen source
  bindings and visible evidence inside the physical target interval. Coordinates,
  omitted bodies and cross-case receipts cannot fabricate a located incident.
- Keep scorer-only labels separate from identical public method inputs. Reuse the
  canonical evaluation types/statistics, retain misses/errors/abstentions in the
  denominator, and keep missing measurements unknown rather than inventing zero.
- Bind method configuration, implementation and limits before execution. Cooperative
  checks cannot preempt arbitrary kernel/provider calls; the controller still owns
  process bounds, provenance and actual exposure authority.
- Finish the smallest runnable local workflow before adding integration breadth.
  A local Python stdio application does not need a forced web UI or database, and a
  repository import does not grant a hosted browser access to local-machine logs.
