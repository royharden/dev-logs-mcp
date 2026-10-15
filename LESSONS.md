# Lessons learned

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
