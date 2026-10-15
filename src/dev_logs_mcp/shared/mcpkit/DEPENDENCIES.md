# Dependencies

- Python 3.12 standard library, including ctypes for native metadata adapters.
- Pydantic 2: strict shared models and JSON Schema. Current root lock resolves 2.14.1.
- google-re2: bounded RE2 matcher; root pin 1.1.20251105. No backtracking-regex fallback.

The root uv.lock is the actual resolved dependency authority. Consumers resolve and
record a compatible lock of their own; this file is not a competing lock. Retain the
root LICENSE/NOTICE and upstream license notices when distributing dependencies.

MCP SDK 2.3.0 belongs to the application's optional transport layer, not these core
modules. No provider SDK, network service, database, model, secret, or sibling project
is a core mcpkit dependency. Standalone consumer installation remains unverified.
