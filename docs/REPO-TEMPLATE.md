# Repository template contract

This repository is the S1 template under construction. Copy stable product files
only from an actual verified commit after the relevant exports pass their tests.
Do not copy parent-shell planning, receipts, exports, registries or credentials.

The common layout includes README, LICENSE, product AGENTS/CLAUDE instructions,
pyproject/uv.lock, src/<package>, fixtures, gold/dev and gold/heldout, results,
scripts/demo.py and scripts/eval.py, tests, CI and docs/LIMITATIONS.md.
Contracts, the five-tool stdio server, bounded parser/index/query pipeline, and mcpkit
primitives are implemented. Gold/results/demo/benchmark scripts, CI, standalone conformance,
detached-consumer checks, and native platform acceptance are still pending. The template
is not yet an approved vendoring publication.

README order: purpose; keyless quickstart; one real example; architecture; generated
results with baselines; model and runtime cost; named limits; agent verification.
Never publish invented numbers. Later scripts generate results and the README table.

S1 owns mcpkit and this template. S2 owns evalkit/gold compatibility, S3 owns
providers/callledger and S5 owns Pointer dispatch. No alternate shared libraries.
Consumers vendor actual approved source commits with VENDORED.md and contract tests;
workspace-relative imports and speculative commit identifiers are forbidden.
