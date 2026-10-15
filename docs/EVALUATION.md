# Deterministic incident evaluation

The `evaluation` package implements the S1 domain adapter and three fixed tool
methods. Its current checks use original toy response transports. Independently
sealed DEV and heldout campaigns, source acquisition, canonical enrichment and
controller provenance are separate work; no diagnosis score is established yet.

Every method receives the same public source alias and symptom hint. Gold
coordinates, expected trace markers, groups and secret registries are scorer-only.
The scripted method lists sources, requests errors, searches literal hint tokens,
then reads around an observed anchor or falls back to tail. The grep baseline
pages oldest-first redacted search and reads around its first observed match.
The naive baseline pages 100 physical lines from the start and advances from the
last line actually returned, including when a response was shortened.

Method configurations bind the implementation digest supplied by the trusted
controller, algorithm version, call/deadline bounds and fixed parameters. The
default client admits at most 64 calls and 30 seconds per case, with post-return
five-second checks per call. Checks are cooperative; they do not preempt an
arbitrarily blocked kernel/provider call. The actual controller must bound its
processes and verify the implementation digest before execution. A changed
method/config/candidate invalidates the corresponding frozen campaign admission.

Attempted and returned calls, observed serialized-frame bytes, elapsed time and
frame origin are recorded. Read counts remain null when any response lacks
trusted read instrumentation. These tool metrics are not a model call ledger;
these methods invoke no model, provider API, file reader or source acquisition.
All dispatches use the supplied transport and public source alias. Reusing the
same method instance for an already attempted item is rejected.

Only references to recorded responses become predictions. The scorer requires
matching case, method, frozen source hash and generation-bearing evidence, with
the expected visible trace on a physical line inside the target interval.
Coordinates without returned text and omitted private/overlong bodies cannot
locate an incident. Errors, stale responses and abstentions remain eligible
non-successes; not-run stays unmeasured. Canonical evalkit outcomes, accuracy and
reporting own the fixed denominator and generic statistics.

Recording a supplied frame does not prove native capture, source immutability,
input normalization, independence or permission to expose heldout material.
The trusted controller owns those facts, actual cost/attempt accounting when a
reply cannot be recorded, and source/receipt binding. Corpus metadata remains
`needs_owner_metadata` until actual owner enrichment is available. Do not invent
history, rewrite sealed labels, follow private provenance paths, or run heldout
from the tuner process. No corpus or provider is acquired by this package.
