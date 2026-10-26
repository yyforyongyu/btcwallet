# Benchmark methodology

Use the same logical Wallet state and completed API operation across backends.
Use lnd's wallet use case for the model. Prepare data separately from each
measured API call. The [reproducibility guide](reproducibility.md) records
exact counts, seed paths, saved storage and environment. The [shared
guide](README.md) gives execution commands.

## Why these datasets

The completed lnd experiment gives the model a concrete source. One 1 BTC
deposit funded 100 channels through successive change outputs. The node closed
98 channels cooperatively and force-closed two with pending HTLCs. This history
includes spent funding outputs, returned funds and resolution transactions.
It represents wallet activity beyond a collection of independent payments.
Settled off-chain payments do not add one wallet transaction or ordinary
address per payment, so the model does not generate that traffic.

Keep the observed relationships between accounts, addresses, keys, history and
unspent outputs. Most ordinary addresses have the used flag. Internal channel
keys stay in separate accounts. The model does not set their used flags.
The model keeps the observed scope and script types. This gives read APIs a
wallet history with channel activity, beyond only live output rows.

The shared cases are `small-node`, `medium-node` and `large-node`. They model
1, 10 and 100 initial funding UTXOs. Each deposit funds 100 channels.

The small case follows the observed endpoint. The larger cases repeat that
normalized history in one Wallet. Accounts stay fixed. Addresses, channel
keys, transaction history and final outputs grow together. These names describe
model sizes, not measured user populations.

The completed lnd observation covers one deposit only. Larger models are
estimates of its scale. They repeat three sweep transactions per deposit. Real
lnd can batch sweeps across deposits, select other fee inputs or consolidate
funds. Do not interpret these cases as measurements of three real lnd
populations.

Read Wallet API benchmarks use these saved datasets as a common base. Each
invocation works on a private restored copy. A method records its request and
any changes to that copy. For a focused parameter study, change the method's
target dimension and keep independent background data fixed. The node cases
change related dimensions together. They do not isolate live UTXO count.

## How the suites connect

Keep the existing kvdb comparison suite in
[wallet/utxo_manager_benchmark_test.go](../../../wallet/utxo_manager_benchmark_test.go).
It compares legacy and maintained Wallet APIs. Keep its original growth
matrix. Each method adds matched cases that consume the shared node
definition. Only these matched cases supply kvdb baselines for the SQL
comparison. When the project retires kvdb, remove the kvdb suite.

Legacy and maintained kvdb must use the same saved database for each node size.
Each gets a private file copy. Legacy reopens it through Loader. Maintained
kvdb reopens it through Manager.
Each implementation calls its native read APIs and unlocks before timing.
Their native setup paths are different because the APIs use different Wallet
runtimes.

The independent SQL suite is in [wallet/bench](../../../wallet/bench).
It creates and restores SQLite and PostgreSQL through their usual Manager
and Store mechanisms. Method entrypoints call the selected public Wallet API.
The SQL suite does not run the kvdb suite or read stored baseline results.
This suite stays usable after kvdb retirement.

The two suites consume the same deterministic [case
builder](../../../wallet/internal/bwtest/bench_cases.go). Match account
selection, scripts, values, transaction links, confirmations, tip and request
filters. Backend IDs and seeding paths can be different.

Compare completed native calls with usual database I/O. This includes
PostgreSQL's client/server work. SQLite runs inside the Wallet process.
PostgreSQL runs in a separate container. The comparison measures these native
configurations and their storage and transport costs.

Use unit and integration tests to check that fixtures and APIs are correct.
Benchmark setup and operations fail on errors. Do not add result or
fixture-content validation to the benchmarks.

For point reads, select a retained cooperative return before measurement.
Choose the smallest txid/index among outputs with the shared cooperative value.
This selects the same address, outpoint and one-input/two-output transaction
shape across implementations. Request preparation does not validate results.

The method report gives its native request, comparison baseline and important
semantic differences. Shared data alone does not establish equivalent API work.
Keep unavailable or unmatched requests explicit. Do not add timed adapters
to make the implementations appear symmetric.

## Timing and profiles

Seed one time per backend, size and fixture revision. Close all database users.
Save that state.

For each invocation, even the first, restore private storage. Start a new
Wallet. The query does not use the seed process's Wallet caches. The first
`b.Loop` resets time and allocation counts after setup. Loop exit stops timing
before cleanup.

Restoration, database readiness, connections, unlock and request preparation
are outside measurement. Timed calls include usual database I/O and the wait
for PostgreSQL. Whole-command wall time includes setup and shutdown and is
not the API latency metric.

After unlock, call the selected API one time without timing or profiling. Use
the same request and active Wallet for later timed calls. This does not
include first-use cache work for each implementation. Otherwise, one slow
first call can fill a duration target while other implementations amortize it
over many calls. These measurements compare repeated reads, not first-call
latency.

A duration is a target, not a hard timeout or a guarantee of multiple calls.
Before you compare repeated-read results, examine their actual iteration
counts. Use the same iteration policy across the compared implementations for
fixed-count groups. Keep single-call diagnostics separate from repeated-read
summaries. The [collection
record](reproducibility.md#serial-schedule-and-collection-record) identifies
the default and important exceptions.

## Serial samples and aggregation

Run one implementation at a time on the same host and architecture. Concurrent
clients compete for CPU, memory and storage bandwidth. PostgreSQL uses
these same resources. Competing Docker or build work can change the measured
latency. Keep affected attempts and repeat samples after that work stops.

Rotate implementation positions. Reverse their order to reduce order bias from
host load, cache state and other changes over a collection. A balanced
schedule distributes positions. It does not prove equal native API work or
remove all measurement bias. Request semantics and completed operations must
match. The [schedule
guide](reproducibility.md#serial-schedule-and-collection-record) distinguishes
the driver's schedule from the actual retained collection groups.

Summarize accepted unprofiled samples for each implementation and dataset.
Repeated-read groups usually use eight samples. Take the median separately for
`ns/op`, `B/op` and `allocs/op`. Do not pool separate collections into a
claimed balanced collection. Do not treat a standalone diagnostic as an
eight-sample median. Evidence identifies group membership and exceptions.

Go allocation metrics measure allocations in the Wallet process and its usual
client work. They do not include PostgreSQL server memory. These are
per-operation Go allocations, not whole-command memory or database-server
resource measurements.

## Ratio interpretation

Compare each metric's median with the report's declared baseline median. For a
value below baseline, divide baseline by measured value. For a value above
baseline, divide measured value by baseline. Baseline and equal values use
`1.00`.

Calculate from the unrounded values. Show two decimals. These descriptive
ratios are not confidence intervals.

Each ratio cell contains only a dot of the specified color and its number,
such as `🟢 1.18`. Use one short legend per report: green below baseline, red
above baseline, white baseline/equal. Do not add direction words, a multiplier
sign or a percentage to each cell. The legend applies to all three metric
columns.

## Separate profiling

After setup and the untimed first call, collect CPU and heap profiles in
separate invocations. Complete the captures before Wallet cleanup. Timer reset
alone does not control profile capture. Profiling adds overhead. Its samples
do not supply the unprofiled result tables.

A post-setup heap baseline separates fixture allocation history from the
workload. Distinguish cumulative allocations from retained heap when you read
the delta. See [artifact analysis](reproducibility.md#artifacts-and-profiles)
for the exact files and sample types. Profiles show measured work. They
do not replace unprofiled latency data.

Read benchmarks share restored data, untimed request preparation, one first
read and the common measurement loop. Only the API call changes. Chain sync
and startup measure lifecycle work and cannot use this repeated-read boundary.

## Chain synchronization

Startup-to-synced measures a fresh native lifecycle discovering a prepared
chain. It uses the [startup dataset](reproducibility.md#startup-chain-dataset),
which preserves the lnd Wallet shape and address distribution while defining
block placement separately from the read snapshots. Shared Wallet inventory
alone does not define a chain workload. Hold the chain, starting metadata,
background traffic, source and completion condition fixed across implementations.

Prepare and mine the target before measurement. Save a closed unfunded native
Wallet at the common chain base. Restore private storage and construct a fresh
Manager, chain source and connections for every sample. Database startup,
physical open, restore, NewManager, mining, random generation and shutdown are
untimed. There is no read warmup. Time Manager.Start, including durable Wallet
loading, through public Info observing native readiness and the exact configured
target hash/height. Legacy times OpenWithRetry, StartDeprecated and SynchronizeRPC
through its equivalent persisted-tip/ChainSynced condition plus live-tip RPC.
The live RPC matches Info's observation work and lets network polling progress
on one processor. Unsuccessful observations yield; they add no completion sleep.

Legacy uses native rescan; maintained kvdb, SQLite and PostgreSQL use full-block
sync. Both kvdb leaves restore the same closed baseline and persist freelists.
The SQL suite owns its usual native lifecycle independently. These paths need
not have artificial structural symmetry. Report only this explicit workload
and mode comparison; do not infer a general ranking of storage backends.

The three nonzero full cases hold the same 204 Wallet graph transactions fixed
and distribute them into 1, 10 or 100 matching blocks within 1,000 blocks. Thus
average graph transactions per matching block changes as 204, 20.4 and 2.04. This
studies placement/clustering with fixed Wallet work, not increasing Wallet
transaction volume. The populated 0% baseline intentionally has no Wallet work.
Treat that boundary explicitly when examining trends; three nonzero points do
not establish general linear scaling. Background payments remain identical.

Coinbase-only empty blocks are a separate control from populated blocks with
no Wallet matches. Both start with the same unfunded metadata, including its
existing addresses and keys. Keep empty-block results outside the populated
hit-ratio relationship. Foreign-only graph transactions are not Wallet hits.

Calibrate block payload by weight and serialized bytes rather than transaction
count alone. The deterministic background payment template models scan load,
while the Wallet graph preserves lnd transaction shapes. Mainnet traffic mixes
and Lightning contract timing/witnesses remain disclosed simplifications.
Inspect real pilot blocks before scaling; never silently substitute lighter
blocks, synthetic Store ingestion, mocks or the legacy stress dataset.

The maintained full-block scanner requests the whole 1,000-block window in one
getblock batch, implying about 2.8 GB of reply hex at this payload before copies
and decoded objects. This requires the explicit startup capacity budget in the
[environment table](reproducibility.md#docker-environment). Keep those fixed
settings across implementations and record them with the measured cohort.
The small pilot establishes validity/reuse, not full-window memory feasibility.

Use 1x for each restored lifecycle. CPU and heap captures are separate 1x runs;
finish capture before Wallet/source teardown. Keep usual database and matched
chain I/O measured. Fixture correctness belongs in tests and separate inspection,
not benchmark assertions. Whole-command duration includes setup; a timeout or
OOM supplies no startup timing or usable profile. Keep failed/excluded attempts
with their actual source revision and never relabel old dense or biased runs.
