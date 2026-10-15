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

The future conformance runner uses an injectable transport profile; it is not yet present.
Neither these unit tests nor a copied directory alone establish application acceptance.
