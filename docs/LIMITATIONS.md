# Current limitations

- W01 only: configuration shape and strict request/result contracts. No operational
  five-tool server, safe opened-handle policy, redaction, index or conformance export yet.
- Schema limits do not prove bounded runtime, filesystem access, redaction or response frames.
- Windows no-recall/handle/change-time checks, Linux conformance, offline scanner and
  guard-sabotage controls remain required unexecuted later gates.
- Pattern redaction will miss unknown secret shapes; it is not a general secret detector.
- Approved FRESHNESS-1: logs above 6 MiB that change continuously may be unavailable
  throughout the writer lifetime. Small files auto-index only after that feature is built.
- UTF-16 logs will be refused with reencoding guidance. Physical lines above 64 KiB
  will be omitted whole and unsearchable, with explicit coverage/omission markers.
- No PyPI publication, remote CI execution, GitHub push, client configuration changes
  or hosted runtime is established by this repository bootstrap.
