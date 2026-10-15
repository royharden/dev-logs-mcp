# mcpkit primitives

Reusable Python primitives for configured-root read authorization, redaction, RE2 matching,
strict envelopes, bounded serialized responses, and tool-schema export/style checks.
Core modules import no application code or MCP transport. The current package remains
under validation; detached-copy/conformance verification and a final vendoring publication
are pending. The version file identifies this source contract, not release acceptance.

Copy the whole directory, its rules/tests/dependency notices, and the repository MIT
license from an explicitly approved source commit. Record that commit, source hashes,
license, destination namespace, and any import-only adaptation in VENDORED.md. Do not
import from a sibling workspace application or copy agent plans/transcripts/credentials.

Consumers supply configured roots/source IDs and adapt domain errors to their transport.
Redaction defaults stay enabled; matching sees redacted text. Budget helpers cap the
actual serialized frame, including duplicate content channels and request-ID overhead.
Transport adapters must preserve their own observed serializer/metadata accounting.

SafePath Windows data access remains unavailable; native metadata diagnostics are not
data authorization or no-recall proof. The Linux LP64 O_PATH/fstatfs successor requires
native verification. See the parent project's LIMITATIONS for the open platform gates.

`conformance/runner.py` accepts an injected async transport profile, strict Case inputs,
an observed response frame, optional measured read counts, and a domain schema/oracle callback.
`conformance/case.schema.json` is generated from the strict case model. Reports retain
case IDs, status, closed reason codes, byte counts, and durations, with no raw frames,
arguments, planted marker values, or exception messages.

Profiles own process cleanup and actual transport/I/O instrumentation. A declaration of
native execution or captured wire is not independent proof. Missing required native,
wire-capture, or measured-read capability is unsupported-required and cannot yield a
complete scoped pass; platform-specific not-applicable cases have a separate denominator.
Callbacks and kernel calls cannot be preempted; late returns are recorded as failures.
An entire non-applicable/empty suite never passes. The reported scope is the supplied
case set, not a claim that every required application case has been supplied.

Current controls cover strict cases, channels/mirror/schema, private-marker leakage,
frame/I/O caps and deadlines, plus actual in-memory eight-case five-tool query behavior.
The three unsafe injected transport controls are synthetic runner tests. Actual app guard
sabotage, native profiles, full page-union/security gates and independent review remain
required. Neither unit controls nor a copied directory alone establish app acceptance.
