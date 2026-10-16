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
controls are not hard-preemption evidence. The separately authorized native run below
now supplies source-profile observations; the original failed measurements stay failed.

Consult [development status](../DEVELOPMENT-STATUS.md) for execution, remaining
qualification work and platform boundaries.

## Observed source-profile run

At exact raw-Git source commit `7d8d095653189b78987cf9450b31d89b3e77556c`, a fresh
offline Linux CPython 3.12.13/glibc 2.36/x86-64 job completed 77 focused controls,
the 64 KiB smoke and both exact 100,000,000-byte inputs. Each input has 97,656
physical lines. Its hashes match the earlier failed inputs. Preparation read exactly
100,000,000 observed bytes per format and took 4.396s/plain and 4.554s/JSONL;
each resulting private cache occupied 911,970 bytes. The new 120-second preflight
bound was in force, while tool calls retained five seconds. These later timings
do not prove a causal throughput improvement over the earlier attempts.

All 600 warm calls succeeded: 30 distinct repeats per tool, format and request
profile. Observed Python reads matched application counters and stayed within
8 MiB; rendered frames stayed within 32 KiB. This table is generated from actual
records, using nearest-rank p95 over all 30 calls per row. **It measures in-process
query/renderer latency, not MCP SDK stdio latency.**

| Format | Request profile | Tail p95 (ms) | Search p95 (ms) |
| --- | --- | ---: | ---: |
| plain_iso | default_request | 28.76 | 49.65 |
| plain_iso | maximum_request | 48.08 | 60.35 |
| jsonl | default_request | 24.65 | 52.04 |
| jsonl | maximum_request | 51.66 | 50.43 |

The eight tail/search row observations met their soft reference targets on this
shared host. That is not production performance qualification or generalization.
Default/maximum profiles vary request parameters, not configurable lower ceilings.

For each format, the sparse match sweep returned exactly 1,006 unique physical
matches across 103 pages and read 836,100,352 bytes in total. The no-match sweep
used 23 pages and read 192,274,688 bytes. Every page stayed at or below 8,388,608
observed bytes and below the full 100 MB source. These repeated-read costs remain
visible; a bounded page does not imply a one-pass whole-source cost.

The largest recorded memory high-water samples were 48,447,488 process RSS bytes
and 324,866,048 cgroup bytes through the last warm call. Cgroup memory includes
the generated file cache. Later final/sweep peaks were not emitted, so the final
whole-job peak remains unmeasured; these are not per-call allocations. Raw process
I/O remained null with FileNotFoundError/errno 2. No zeros were substituted and
no reason for that missing kernel interface is inferred.

Hardware context: shared Intel Core i7-12700H Windows/Docker Desktop host,
14 physical/20 logical cores and 42,619,097,088 physical RAM bytes reported by
the host. The job had one CPU quota, 512 MiB/64 PID bounds, read-only root/source/
wheels, generated-only tmpfs and no network, ports or persistent volumes. Hardware
was not exclusive. The owned job completed in 291.359s, exited without OOM,
was removed and released its ledger claim. Exact observation review is pending.

The configurable-limit grid, complete process I/O/final memory capture, native
production preemption, sustained stress, Windows, evaluation and full application
acceptance remain open. No scanner or model was invoked by this benchmark.
