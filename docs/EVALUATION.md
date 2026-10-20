# Deterministic incident evaluation

The `evaluation` package implements the S1 domain adapter, three fixed tool
methods and an in-memory controller using canonical evalkit comparison/reporting.
Its current checks use original handcrafted response transports. Independently
sealed DEV and heldout campaigns, source acquisition and canonical enrichment
remain separate work; no diagnosis score is established yet.

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

`controller.evaluate` defaults to explicit not-run rows and never constructs a
transport unless the caller passes `execute=True`. Admission pins the candidate,
canonical manifest, parsed scorer/public/source input bundle, installed domain
and method source bytes, and all three method configurations. The caller supplies
the observed candidate commit; this module does not invoke Git or attest running
Python objects. A parsed-input digest does not replace verification of original
corpus bytes against the manifest. The controller validates all case bindings and
available public source views before dispatch, snapshots mutable inputs, and
retains stale/unavailable cases in the fixed denominator. Canonical heldout seal,
DEV lock, method configuration and caller-owned durable exposure history checks
remain mandatory; heldout candidate identity is checked as well. Do not use an
in-memory history double for a real heldout campaign.

The transport factory receives public case/method/source IDs only. Construction
failures and invalid replies retain attempted-call accounting even when no
evidence can be recorded. Metrics retain the actual frame origin and unknown
read counts. Results include private predictions/outcomes and per-case tool
metrics; `public_aggregates()` emits only the frozen S1 aggregate allowlist.
The manifest must declare that exact supported publication policy.

`uv run python scripts/eval.py --preflight` prints installed method/configuration
identity with `status: not_measured`. This entry point has no campaign loader,
arbitrary plugin import or native source adapter. An authorized caller can invoke
the controller with independently admitted in-memory inputs and a trusted
transport. No actual campaign or source acquisition is established by preflight.

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

`evaluation.admission.evaluate_from_corpus` adds an explicit private-input entry
over the same controller. The caller supplies a `CorpusAdmission` with the exact
controller pins, split, source-binding digest, public-input digest and available
checksum-bearing corpus rights/authority references. Each `SourceBinding` pins
the source reference, manifest artifact namespace, split and rights/authority
references. These are caller declarations, not authentication or independently
verified permission. The caller must authorize the exact corpus root/split before
calling; provenance reference paths are never followed.

The adapter reuses canonical `load_corpus` for the original JSONL byte hash,
bounded parsing, order, membership and domain checks. It hashes immutable source
snapshots already acquired by the caller, joins their hashes and exact case
membership to manifest artifacts, and rejects missing/extra bindings. Both DEV
and heldout must be nonempty with disjoint groups and source bytes. This validates
declared partition isolation, not semantic independence of generated families.
Default execution stays not-run. Heldout requires the existing admission/history
ports, and canonical controller checks still apply. No durable history store,
campaign, corpus generator, native source reader, CLI campaign loader or Windows
access capability is added. Verified supplied snapshots do not attest that a
transport consumed those same bytes; actual capture provenance and process
bounds remain the caller's responsibility.
