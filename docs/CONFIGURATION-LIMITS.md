# Per-instance tool limits

An optional `[tool_limits]` block may tighten the application's fixed upper ceilings.
Omitting it preserves the original limits. Unknown fields, booleans, nonfinite times,
numeric strings and values above the ceilings are rejected before source authority
is constructed.

```toml
allowed_roots = ["logs"]

[[sources]]
id = "web"
path = "logs/web.log"

[tool_limits]
read_bytes = 2097152
lines = 3
frame_bytes = 8192
seconds = 1.0
```

| Field | Default / maximum | Minimum | Applies to |
| --- | ---: | ---: | --- |
| read_bytes | 8388608 | 1 | One tool call's source/index/helper reads |
| lines | 500 | 1 | Unique physical evidence lines in the rendered tool result |
| frame_bytes | 32768 | 8192 | Complete final tools/call reply, including SDK serialization |
| seconds | 5.0 | Positive finite value | One cooperative queue plus execution deadline |

The global catalog/control-frame ceiling remains **32768 bytes**. The lower
`tool_limits.frame_bytes` value applies to tool results, not to the five-schema
catalog or discovery replies. The 8192-byte minimum reserves room for bounded
mandatory metadata, request-ID escaping and the pinned SDK's extra serialization.
Do not interpret it as a lower all-protocol-frame ceiling.

Queue admission starts the same deadline used by the engine. An injected caller
budget cannot widen read allowance or reset the deadline after queue time. Rendering
takes the minimum of the instance and caller bounds; success, failure and BUSY
replies share the lower caps. The final SDK-byte guard checks tool replies again.
These remain cooperative checks, without synchronous-kernel-call preemption.

Large or contextual requests may need whole-unit truncation or a narrowing hint
under a tighter profile. A lower read budget can require explicit preparation even
for a small source, and a requested evidence unit may be unable to fit the smaller
frame/line cap. Exported tool schemas describe the global maximums, not guaranteed
availability under every instance setting. Default request arguments are not a
promise of an untruncated response when limits are tightened.

Explicit `index-source` preparation remains a separate, finite 120-second shared
budget across at most two attempts and up to 1 GiB total reads. No MCP request can
invoke that operation. Configuration fingerprints include the new limits, so cache
namespaces/generations/cursors change when a limit changes. Adding default limit
fields also changes fingerprints from the earlier implementation; prepare large
sources again after upgrading. Existing cache files are not silently reinterpreted.

Strict configuration/query controls and actual SDK stdio with synthetic memory have
run. At raw-Git source `761139557b6a06281e4969bc8a17d95e5973b4ff`, five required
configured-file controls also passed on Linux CPython 3.12.13/glibc 2.36/x86-64:

- Authorized-file read admission refused a 128-byte allowance before body reads;
  removing that one in-process admission guard produced over-budget reads.
- Changed limits invalidated cache/generation/cursor bindings.
- Plain-ISO and JSONL files each passed all five actual CLI stdio tools at 2 MiB,
  three physical lines, 8192 tool-frame bytes and one second, with stable redaction
  and unknown-source refusal. Catalog/control frames retained the global ceiling.
- A 64 KiB, one-repeat benchmark smoke retained its final workload snapshot.

The largest recorded tool reply was 3834 bytes; catalog replies were 25813 bytes.
The reduced-read control observed zero baseline source-body bytes and 35000 bytes
after the one admission mutation. These are the specific configured-file/control
observations, not complete kernel I/O or all-path ceiling qualification.

These five cases are included in the complete 658-case suite: 641 passed, 17 named
Windows-only skips, zero failures/errors, exact collection/JUnit identities.
All 115 mounted tracked files matched raw Git. This is author evidence awaiting
independent review, limited to generated tmpfs files and that source/runtime profile.
It does not establish all filesystems, Windows, a performance grid or full-app acceptance.
The earlier native attempt timed out during its 60-second offline install before
tests. A separately authorized fresh setup copied and hash-checked the same 34
wheels into owned tmpfs, with a 120-second install ceiling, and completed. The
earlier failure and unknown cause remain preserved. No large benchmark was repeated,
and the older benchmark's fixed-profile values and missing final peaks are unchanged.
