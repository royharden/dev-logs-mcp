# Tool descriptions and transport contract

Generate `tools.json` with `dev-logs-mcp export-tools --out tools.json`; verify it
with `dev-logs-mcp export-tools --check tools.json`. Exporting needs no log file,
provider, listener or running server. The catalog contains exactly list_sources,
tail, search, read_range and errors with strict input and version-one output schemas.
Presentation titles and defaults are removed from schemas; validation constraints,
data properties, constant values and enum literals are retained. Runtime request
models still supply defaults and reject coercion, including bool-as-int.

Each description has ordered Use, Inputs, Returns, Bounds, Trust and Failures
sections, is at most 1,400 characters and declares untrusted content. Reusable
`mcpkit/style_rules.py` checks this syntax; it does not establish semantic correctness.
Annotations are readOnlyHint=true, destructiveHint=false, idempotentHint=true,
openWorldHint=false. They describe the implementation; they are not enforcement.

`dev-logs-mcp serve CONFIG` runs the official locked MCP SDK over stdio only.
There is no HTTP server or shell-execution tool. Config-relative paths bind to
the actual config file directory. Source directories are discovered one level
at startup, restricted by configured extensions. Restart to discover new names;
existing small files can refresh their generation after ordinary appends.
Directory inventory exceeding 1,000 entries, 100 configured files overall, or
an unsafe matching entry is refused rather than silently accepted as a partial catalog.
List metadata never reads a source body. Readable status is a current metadata/
permission observation; every later read must independently pass SafePathPolicy.

Tail's `lines` selects the newest physical window before applying optional since.
Search's since is inclusive and until exclusive; offset-free input uses the
configured timezone. No temporal monotonicity is assumed. Search matches physical
lines after redaction; context may include lines outside the temporal filter.
Errors counts parsed severity headers only and aggregates occurrences within the
reported coverage. Whole-generation counts require all pages of that generation.
An unknown-format word ERROR is not a severity label.

Responses contain a structured envelope and identical JSON in one text block.
The engine redacts before matching, grouping or serialization. Generation-bound
physical line/byte coordinates identify source evidence, not a generic Pointer.
Continuations bind the process, source, generation, configuration, tool, query,
filters and direction. Restarts or changed queries invalidate cursors.
Response shrinking preserves whole evidence units and resumes before the first
omitted occurrence; a single unit that cannot fit returns LIMIT_EXCEEDED instead
of an endlessly repeating empty page. Read-range truncation supplies a physical
line hint because its request schema has no cursor argument.

At most four calls execute and sixteen wait FIFO. Queue time consumes the same
five-second cooperative deadline as source work; full/expired queues return BUSY.
Kernel calls cannot be forcibly preempted by this deadline. A stopped scan can
return completed redacted units with truthful incomplete coverage and continuation.
Source/cache/guard/context bytes share one 8 MiB tool-call budget. Private indexes
contain offsets, hashes and finite parser/PEM state, never raw source text or keys.
The index allocation ceiling is 262,144 physical lines and 4 MiB encoded cache,
in addition to the 1 GiB source ceiling. Dense sources can hit the allocation cap.

The adapter reserves 2 KiB inside the 32 KiB response allowance for the SDK's
modern resultType/serverInfo fields. Its final writer checks the SDK's actual
serialized UTF-8 frame plus newline, including ID and both content channels.
All SDK protocol-error details/data are replaced with value-free errors before
the wire. Input is a newline-terminated UTF-8 frame of at most 64 KiB. Oversized,
unterminated or invalid-UTF8 input terminates the stdio session. Request IDs must
be safe JSON integers or strings of at most 256 UTF-8 bytes. Application failures
set isError; schema/protocol failures remain MCP errors. Diagnostics never go to
protocol stdout.

Windows data authorization/noRecall and private-cache ACL proof remain unavailable.
The production Windows adapter refuses data access before source I/O; list_sources
reports unavailable metadata. Metadata diagnostics and synthetic-memory stdio
tests do not establish successful native log reading. POSIX and full application
acceptance require separately recorded real-platform/conformance/evaluation receipts.
