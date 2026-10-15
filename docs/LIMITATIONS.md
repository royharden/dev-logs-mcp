# Current limitations

- Windows data authorization is unavailable. Metadata-only native probes do not prove
  safe data opening or cloud no-recall behavior. The server refuses data requests before
  source metadata/data I/O on Windows. Three native metadata stability checks have failed;
  the required symlink fixture also lacks privilege. These are open capabilities, not passes.
- Linux uses no-follow O_PATH probes, a fixed-buffer LP64 fstatfs allowlist, pinned data
  reopening, and identity/containment checks. Native verification of this successor is
  pending. Unsupported ABI, missing guarantees, FUSE, overlay, and network storage fail closed.
- The earlier Linux test attempt timed out during container start and yielded no test
  verdict. A later attempt rejected the retained dependency tree before pytest: the
  installer had hashed payload files before adding its receipt, while the verifier
  included that receipt. A receipt-aware successor is prepared but has not run;
  other actual volume changes have not been ruled out. Dependency setup or metadata
  readiness does not establish product runtime support.
- Five SafePath and two cache/catalog native POSIX checks remain pending on the Windows
  development host. Independent conformance, sabotage controls, offline scanner,
  heldout evaluation, clean-wheel and full detached-runtime checks remain required gates.
  A detached pure-core/synthetic-conformance subset passed with the owner app and MCP
  SDK imports blocked, using existing dependencies. It did not execute native path tests.
- Large files above 6 MiB require a stable explicit index. Any change invalidates the
  generation and cursors. Continuously changing large logs may be unavailable throughout
  the writer lifetime. Small files can auto-index within the per-call budget.
- The 8 MiB application read budget, 32 KiB full serialized response cap, and cooperative
  five-second deadline require further native all-path/performance proof. Fixed metadata
  syscalls are distinct from file-body reads. Kernel calls cannot be preempted by Python.
- Redaction covers configured/default secret shapes, with whole-line omission on uncertainty;
  unknown secret shapes can be missed. Placeholder type, length, and four HMAC hex digits
  disclose limited structure and may collide. They are not a secrecy or equality proof.
- Matching operates on redacted text. Bodies above 64 KiB are omitted whole and cannot
  match. UTF-16 BOM and binary/NUL sources are refused. Physical LF/CRLF and UTF-8 are supported.
- JSON numeric severity is supported; numeric epoch timestamps are metadata fallback.
  Invalid JSON timestamps clear that event's timestamp and retain independently valid
  severity, without inheriting a prior record. Continuation lines inherit available metadata.
- Tail time filters apply within the requested newest physical-line window. Output
  truncation, scan completeness, and semantic exclusions are separate coverage properties.
- Index checksums detect corruption, not a malicious same-owner cache rewriter. An OS
  administrator's metadata-preserving edits outside checked chunks are outside the guarantee.
- No model calls, command-execution tool, URL fetching, dynamic roots expansion, log writing,
  browser runtime, public package publication, remote CI run, GitHub push, client configuration
  changes, or hosted deployment are established by this local implementation.

Development is paused. See [development status](../DEVELOPMENT-STATUS.md) for the
remaining demo, controller, security, performance and release work.
