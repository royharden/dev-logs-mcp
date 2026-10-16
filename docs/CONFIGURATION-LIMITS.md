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
run. The prepared native configured-file controls require actual Linux execution;
their presence is not a platform pass. This construction does not relabel the
older 011 benchmark's fixed-profile observations or establish a performance grid.
