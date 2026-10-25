# Benchmark methodology

Use the same logical Wallet state and completed API operation across backends.
Prioritize lnd's wallet use case. Keep data construction separate from the API
being measured. The [reproducibility guide](reproducibility.md) records exact
counts, seed paths, saved storage and environment. The
[shared guide](README.md) owns execution commands.

## Why these datasets

The completed lnd experiment gives the model a concrete source. One 1 BTC
deposit funded 100 channels through successive change outputs. The node closed
98 channels cooperatively and force-closed two with pending HTLCs. This history
includes spent funding outputs, returned funds and resolution transactions.
It represents wallet activity beyond a collection of independent payments.
Settled off-chain payments do not add one wallet transaction or ordinary
address per payment, so the model does not generate that traffic.

Keep the observed relationships between accounts, addresses, keys, history and
unspent outputs. Ordinary addresses are mostly used. Internal channel keys
remain in separate accounts and are not marked as ordinary used addresses.
The model keeps the observed scope and script types. This gives read APIs a
wallet history with channel activity, beyond only live output rows.

The shared cases are `small-node`, `medium-node` and `large-node`. They model
1, 10 and 100 initial funding UTXOs. Each deposit funds 100 channels. The
small case follows the observed endpoint. The larger cases repeat that
normalized history in one Wallet. Accounts stay fixed; addresses, channel
keys, transaction history and final outputs grow together. These names describe
model sizes, not measured user populations.

The completed lnd observation covers one deposit only. Larger models estimate
its scale. They repeat three sweep transactions per deposit. Real lnd can batch
sweeps across deposits, select other fee inputs or consolidate funds. Do not
interpret these cases as measurements of three real lnd populations.

All Wallet API benchmarks use these saved datasets as a common base. Each
invocation works on a private restored copy. A method records its request and
any changes to that copy. For a focused parameter study, vary the method's
target dimension and keep independent background data fixed. The node cases
vary related dimensions together; they do not isolate live UTXO count.

## How the suites connect

Keep the existing kvdb comparison suite in
[wallet/utxo_manager_benchmark_test.go](../../../wallet/utxo_manager_benchmark_test.go).
It compares legacy and maintained Wallet APIs. Preserve its original growth
matrix. Each method adds matched cases that consume the shared node definition.
Only these matched cases supply kvdb baselines for the SQL comparison.
Remove the kvdb suite when kvdb is retired.

Legacy and maintained kvdb must use the same saved database for each node size.
Each gets a private file copy. Legacy reopens it through Loader. Maintained
kvdb reopens it through Manager.
Both call their native read APIs and unlock before timing. Their native setup
paths differ because the APIs use different Wallet runtimes.

The independent SQL suite is in [wallet/bench](../../../wallet/bench).
It creates and restores SQLite and PostgreSQL through their normal Manager
and Store mechanisms. Method entrypoints call the selected public Wallet API.
The SQL suite does not run the kvdb suite or read stored baseline results.
This suite remains usable after kvdb retirement.

Both suites consume the same deterministic
[case builder](../../../wallet/internal/bwtest/bench_cases.go). Match account
selection, scripts, values, transaction links, confirmations, tip and request
filters. Backend IDs and seeding paths can differ. Compare completed native
calls with normal database I/O, including PostgreSQL's client/server work.
SQLite runs inside the Wallet process. PostgreSQL runs in a separate container.
The comparison measures these native configurations, including their storage
and transport costs.

Unit and integration tests own fixture and API correctness. Benchmark setup
and operations fail on errors. Do not add result or fixture-content validation
to the benchmarks.

For point reads, select a retained cooperative return before measurement.
Choose the smallest txid/index among outputs with the shared cooperative value.
This selects the same address, outpoint and one-input/two-output transaction
shape across implementations. Request preparation does not validate results.

The method report states its native request, comparison baseline and material
semantic differences. Shared data alone does not establish equivalent API work.
Keep unavailable or unmatched requests explicit rather than inventing timed
adapters to make the implementations appear symmetric.

## Timing and profiles

Seed once per backend, size and fixture revision. Close and save that state.
Restore private storage and start a fresh Wallet for every invocation, including
the first. This prevents the seed process's Wallet caches from carrying into
the query. The first `b.Loop` resets time and allocation counts after setup.
Loop exit stops timing before cleanup. Restoration, database readiness,
connections, unlock and request preparation are outside measurement. Timed
calls include normal database I/O and waiting for PostgreSQL. Whole-command
wall time includes setup and shutdown and is not the API latency metric.

Call the selected API once after unlock, without timing or profiling. Use the
same request and active Wallet for later timed calls. This excludes first-use
cache work for every implementation. Otherwise, one slow first call can fill
a duration target while other implementations amortize it over many calls.
These measurements compare repeated reads, not first-call latency.

A duration is a target, not a hard timeout or a guarantee of multiple calls.
Inspect actual iteration counts before interpreting repeated-read results.
Fixed-count groups must use the same iteration policy across the compared
implementations. Keep single-call diagnostics separate from repeated-read
summaries. The
[collection record](reproducibility.md#serial-schedule-and-collection-record)
identifies the default and material exceptions.

## Serial samples and aggregation

Run one implementation at a time on the same host and architecture. Concurrent
clients compete for CPU, memory and storage bandwidth, including the resources
used by PostgreSQL. Competing Docker or build work can change the measured
latency. Retain affected attempts and repeat samples after that work stops.

Rotate and reverse implementation positions to reduce order bias from host
load, cache state and other changes over a collection. A balanced schedule
distributes positions; it does not prove equal native API work or remove all
measurement bias. Request semantics and completed operations still need to
match. The
[schedule guide](reproducibility.md#serial-schedule-and-collection-record)
distinguishes the driver's schedule from the actual retained collection groups.

Summarize accepted unprofiled samples for each implementation and dataset.
Repeated-read groups normally use eight samples; take the median separately
for `ns/op`, `B/op` and `allocs/op`. Do not pool separate collections into a
claimed contemporary balanced run, or treat a standalone diagnostic as an
eight-sample median. Evidence identifies group membership and exceptions.

Go allocation metrics cover the Wallet process, including its normal client
work. They exclude PostgreSQL server memory. These are per-operation Go
allocations, not whole-command memory or database-server resource measurements.

## Ratio interpretation

Compare each metric's median with the report's declared baseline median.
For a value below baseline, divide baseline by measured value; for a value
above baseline, divide measured value by baseline. Baseline and equal values
use `1.00`. Compute from the unrounded values, then show two decimals.
These descriptive ratios are not confidence intervals.

Each ratio cell contains only a colored dot and its number, such as `🟢 1.18`.
Use one short legend per report: green below baseline, red above baseline,
white baseline/equal. Do not add direction words, a multiplier sign or a
percentage to each cell. The legend applies to all three metric columns.

## Separate profiling

Collect CPU and heap profiles in separate invocations after setup and the
untimed first call, before Wallet cleanup. Timer reset alone does not control
profile capture. Profiling adds overhead; its samples do not supply the
unprofiled result tables.

A post-setup heap baseline separates fixture allocation history from the
workload. Distinguish cumulative allocations from retained heap when reading
the delta. See [artifact analysis](reproducibility.md#artifacts-and-profiles)
for the exact files and sample types. Profiles explain measured work; they
do not replace unprofiled latency data.

Read benchmarks share restored data, untimed request preparation, one first
read and the common measurement loop. Only the API call varies. Chain sync
and startup measure lifecycle work and cannot use this repeated-read boundary.
