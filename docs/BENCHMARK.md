# Native benchmark observations

`scripts/bench.py` generates separate exact-size plain-ISO and JSONL logs and calls
the actual application in process. It records the real renderer's frame sizes;
it does not capture MCP SDK stdio. No model, network or personal log is involved.

From a qualified Linux/Python 3.12 source environment:

```sh
uv run python scripts/bench.py --size-bytes 100000000 --repeats 30 --output /absolute/path/to/new-benchmark.jsonl
```

The parent output directory must exist. The command creates a new JSONL file and
never overwrites an existing one. Each measurement is flushed so an interrupted
job leaves partial observations rather than a completed result. Generated logs and
private index caches live temporarily under ignored `fixtures/generated/bench`.
They are removed when the benchmark exits normally or through a handled failure.
An external supervisor must enforce process, memory and runtime bounds, including
cleanup if it terminates the process. The script's aggregate deadline is cooperative.

The default size is exactly **100,000,000 bytes per format**, with complete LF-ended
records, recorded source hashes and known physical-line/match denominators. It records:

- Cold tail behavior and explicit index preparation time, observed reads and cache size.
- Thirty warm calls per tool, format and request profile, retaining failed calls in
  nearest-rank p50/p95 latency calculations. Empty measurements remain unknown.
- Default and maximum **request parameters**. List-sources/errors use identical
  fixed parameters in both profiles. Configurable lower application ceilings are
  not implemented or qualified; this is not the complete planned configuration grid.
- Match and no-match source-pagination totals, unique-cursor checks, expected match
  counts, page/read costs and explicit incomplete/failure outcomes.
- Actual Python `os.read` return counts, application-reported reads, rendered output
  sizes, raw process I/O deltas and available process/cgroup memory high-water marks.

The `os.read` observer includes source/index/cache reads but cannot see every native
library read. `/proc/self/io` counters include observer overhead; tmpfs physical I/O
may legitimately be zero. RSS is a process high-water mark and cgroup peak includes
the job's file cache and other memory; neither is a per-call allocation measurement.
The script does not claim production preemption, captured wire bounds, sustained
stress coverage or a complete process-I/O proof.

Exit 0 means observations completed without recorded operation/bound failures;
exit 1 retains completed failures, exit 2 means incomplete, and exit 3 means this
native profile is unsupported-required. Windows is unsupported-required. A run with
smaller inputs or fewer repeats is a smoke check, never the required benchmark.
No exit code certifies performance or application acceptance. The planned reference
targets are p95 250 ms for tail and 1000 ms for a search page; every summary retains
whether those soft targets were met.

The first native run passed 12 controls and a 64 KiB smoke (20 warm calls/four
sweeps). At source commit `4d7a2c846bc3a0d2373e88a4c0de11039349b15e`, both exact
100 MB inputs then failed explicit preparation with `INDEX_INCOMPLETE` after about
five seconds. Warm calls and full-source sweeps did not execute; no p50/p95 exists.
Process I/O counters were unavailable and remain null; observed Python reads and
memory peaks are retained separately. The owned job was removed/released.

The implementation now separates explicit preparation into one 120-second
cooperative budget shared across its two possible attempts. MCP calls and their
small-file auto-indexing retain the five-second budget. Seventy-seven focused
query/index/benchmark controls pass, including a six-second explicit retry, unchanged
tool timeout and refusal after the finite preparation deadline. These clock/memory
controls are not native throughput or hard preemption evidence. A new native large
run is pending; the original failed measurements are not relabelled.

Consult [development status](../DEVELOPMENT-STATUS.md) for execution, remaining
qualification work and platform boundaries.
