# Canonical evalkit provenance

Source: receipt-field-review, commit249262839c4247ff37cc5a75c6a89a422738c759,
tree e60e8ba5efef185a6706c5d266ce3a1ccad5c553. License: MIT, retained as LICENSE.
Canonical directory: src/rfr/shared/evalkit. Consumer: src/dev_logs_mcp/shared/evalkit.
All eleven published runtime/schema/README files are copied byte-for-byte, with relative
imports unchanged. This provenance file and the retained license are additional files.

Nine published synthetic conformance files are mapped from tests/evalkit to
tests/vendor_evalkit. Changes are limited to consumer namespace/root mappings, import
ordering and line wrapping required by that longer namespace. Moved tests keep the
original owner/provider/network guards and additionally forbid the consumer app namespace.
No expected outcomes, formulas, resampling count, support policies or test selection changed.

The source README documents the canonical capabilities and their limits. This copy does
not author independent heldout data, prove human/rights provenance, provide a domain
diagnostic scorer, or authorize a live/provider run. Synthetic component controls establish
only their actual executed scope. The log application's evaluation adapter is separate work.

Keep runtime updates source-owned: adopt a new explicit canonical publication and rerun
the complete mapped plus detached positive/negative controls. Do not fork the generic math,
weaken its fixed-population/heldout guards, or import a sibling workspace application.

Exact source and consumer byte hashes (SHA256):

| Original path | Source | Consumer |
|---|---|---|
| src/rfr/shared/evalkit/README.md | 1308c679caa5413229ba41de0e6fc4f9cdfd8d76fcb66c0cb1aa4597d2dade94 | 1308c679caa5413229ba41de0e6fc4f9cdfd8d76fcb66c0cb1aa4597d2dade94 |
| src/rfr/shared/evalkit/__init__.py | 3017cebcf1f80d410a61712cd8207c1803e09954936ce33238d886760683843e | 3017cebcf1f80d410a61712cd8207c1803e09954936ce33238d886760683843e |
| src/rfr/shared/evalkit/corpus.py | 427ade409f4fb83b59a2d9952c890cb830096af948e1dc9d393a8aef47c23fa0 | 427ade409f4fb83b59a2d9952c890cb830096af948e1dc9d393a8aef47c23fa0 |
| src/rfr/shared/evalkit/identity.py | 5897c07d4b0f5d55dd8fee8cb74a325caaebc03b9e70bbf9c426c431d968f1b2 | 5897c07d4b0f5d55dd8fee8cb74a325caaebc03b9e70bbf9c426c431d968f1b2 |
| src/rfr/shared/evalkit/interfaces.py | d23bc8be5188a968388272580b259ad4af4b1a4cbf393be52d7933514235ed9d | d23bc8be5188a968388272580b259ad4af4b1a4cbf393be52d7933514235ed9d |
| src/rfr/shared/evalkit/models.py | b18613383987a24569e7a9a133b2c212d858c2cf9ee147720b350c06126596c4 | b18613383987a24569e7a9a133b2c212d858c2cf9ee147720b350c06126596c4 |
| src/rfr/shared/evalkit/reporting.py | 96d439870fe13d5c2ff5064d34eeb66fd5a96cf86fa5e5983ba243a6279aa283 | 96d439870fe13d5c2ff5064d34eeb66fd5a96cf86fa5e5983ba243a6279aa283 |
| src/rfr/shared/evalkit/resampling.py | 005c21b6d9f113db22132f0a660c3a2713e5aeaffb4dbb3c4c5349d66c194619 | 005c21b6d9f113db22132f0a660c3a2713e5aeaffb4dbb3c4c5349d66c194619 |
| src/rfr/shared/evalkit/runner.py | b3a9078cf3265d750296907572dfeb66de780c01028b715cfdafb39dbad7bccb | b3a9078cf3265d750296907572dfeb66de780c01028b715cfdafb39dbad7bccb |
| src/rfr/shared/evalkit/schema.json | b44b9f4cea1b90d6524ddf9aa56327667a92340810b19000bb8d47702695ffb7 | b44b9f4cea1b90d6524ddf9aa56327667a92340810b19000bb8d47702695ffb7 |
| src/rfr/shared/evalkit/statistics.py | 9e9ec5e9ba86489c8938a87bd064debbedc143126952959729ab46fd624784dc | 9e9ec5e9ba86489c8938a87bd064debbedc143126952959729ab46fd624784dc |
| LICENSE | 431665582156c442d0448d1f5cd2e45663ab96e6cf098711ffa58c4bb01b69e6 | 431665582156c442d0448d1f5cd2e45663ab96e6cf098711ffa58c4bb01b69e6 |
| tests/evalkit/conftest.py | fa889c24ed0c5599792de4f9a46dee7d09d8e9261ead18804bc1175b32507bff | fa889c24ed0c5599792de4f9a46dee7d09d8e9261ead18804bc1175b32507bff |
| tests/evalkit/test_corpus.py | c6127c483acb8c6fc25887bd677243b5297e275941f4fed461d659b6bfad0d18 | ec43430a7fdfceb25c5e913c2983b280335fe622e86f32989d90dbd501a68b57 |
| tests/evalkit/test_evalkit_detached.py | 9ce522799442e9acdc1a17b946ce4601205094df146725d27e20ea1eae23bcf1 | 735d4000db89d5354cd94f38d2a86d649c0fc81059546493e12f434ce635aacb |
| tests/evalkit/test_evalkit_moved_suite.py | 1ea3f864073ed745001fe00c9996f50d0f2eaaa665d1a5bdb92f6a4a6b84f2ea | e2c24b96272b63e8f7cecbfff57fd276895ded7ffe3656332a12976d3ad9cd8a |
| tests/evalkit/test_heldout.py | e80a02fc8e1ff5e81b007de3d87534eb36b0001dadf2251a3de0a246360e0528 | 9e79bf1b22890b5df99f777c2d02e3a75b47559641e758ed4c0aca1cbfe709a3 |
| tests/evalkit/test_reporting.py | a5b0a537c7b0593fa7bab210d8e9e79c9aba6d462dfb3895f211d30293aa44b9 | 5a8d0c49c16f502d1337962f22fdb5803eb92e98c126a6f5cb49ccbf0180a1ce |
| tests/evalkit/test_resampling.py | 64739c9b0b274542717a19285dd27968442d782979f138345c4e113861d54cef | c8f8d8ef3b00a84735c838310d3241cb15db2096ad1de105c2267749ccfdbdab |
| tests/evalkit/test_runner.py | 365b553de35064978cb488049627cd09cf9de2b4c3adc59502c97244e8877a03 | 1f0789e377af7d0f9e0338847a4d9bbb8c1911e2966cb95c64ae33d454a618c6 |
| tests/evalkit/test_statistics.py | c786947db47453f532a63894679d7b57886e4a2a5bdd3db6e03e582ae343ab65 | 9f9df79cdf57977239607fee65350de1a32b0e606f7ba3d60c6e9f90b56565aa |
