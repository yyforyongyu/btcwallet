# Benchmarks

Use shared node datasets for Wallet read benchmarks. Prepare each dataset one
time per backend and fixture revision. Reuse saved data across methods and
performance changes. Use separate lifecycle benchmarks for chain sync and
startup.

- [Methodology](methodology.md): dataset rationale, measurement boundaries,
  serial sampling, aggregation and ratio interpretation.
- [Reproducibility](reproducibility.md): environment, schedules, collection
  exceptions, saved fixtures, evidence and profile artifacts.
- [Record template](template.md): short API reports with measured sources,
  result tables and comparison notes.

The existing `wallet` suite compares legacy and maintained kvdb calls.
Use `wallet/bench` for independent SQLite and PostgreSQL public API benchmarks.
Matched cases use the same logical data and native runtimes. Original kvdb
comparison cases keep their own fixtures. Remove that suite when kvdb retires.

## Select a benchmark

Run commands from the repository root with Docker available. The generic
framework accepts an exact Go package and benchmark pattern. It works without
API consumers. This compile-only example checks the command without data work:

```sh
# An explicit empty benchmark pattern builds the package without a workload.
BENCH_PACKAGE=./wallet BENCH_CASE='^$' \
  make bench method=compile-only db=kvdb case=smoke
```

The framework provides these friendly method selectors:
`list-unspent`, `get-utxo`, `list-addresses`, `get-address-info`, `get-tx`,
`list-txns`, `get-account` and `list-accounts`. Use these selectors only when
the related benchmark consumer is present. Supply explicit
`BENCH_PACKAGE` and `BENCH_CASE` inputs together. They take precedence over
friendly selectors and select one benchmark case. Use friendly selectors
for collection shortcuts.

Select `legacy`, `kvdb`, `sqlite` or `postgres` for one implementation.
Friendly selectors select the installed native benchmark for each backend.
Explicit package/pattern inputs take precedence over friendly mapping.
Native request semantics and the chosen comparison baseline belong in each API
report. The original kvdb comparison matrices stay available.

During development, use one affected backend and the default `smoke` case.
Use unit tests for correctness. Complete code review.
Before full preparation or measurement, get run approval.

```sh
# Replace the method label to check another installed read consumer.
method=list-unspent
make bench method="$method" db=sqlite case=smoke duration=1x
```

## Collect timing results

Select the shared full cases explicitly. See the
[timing policy](reproducibility.md#serial-schedule-and-collection-record)
and [sampling rationale](methodology.md#serial-samples-and-aggregation).

```sh
# Preserve stdout/stderr and keep each run under its recorded label.
method=list-unspent
run_label=read-baseline
mkdir -p /tmp/btcwallet-bench/"$run_label"
make bench method="$method" db=all \
  case="small-node medium-node large-node" duration=3s \
  out=/tmp/btcwallet-bench/"$run_label" \
  2>&1 | tee /tmp/btcwallet-bench/"$run_label"/timing.log
```

Keep each invocation's raw command and output in its run evidence. Use the
[report template](template.md) for each API record.

## Collect profiles

Use one backend/case, or `db=all` and `profile=all` for available benchmarks.
See [profile interpretation](methodology.md#separate-profiling) and
[artifact details](reproducibility.md#artifacts-and-profiles).

```sh
# Reuse the saved data, then capture only the prepared API workload.
method=list-unspent
run_label=read-profiles
for backend in legacy kvdb postgres sqlite; do
  make bench method="$method" db="$backend" case=small-node \
    profile=cpu duration=15s out=/tmp/btcwallet-bench/"$run_label"
  make bench method="$method" db="$backend" case=small-node \
    profile=mem duration=3s out=/tmp/btcwallet-bench/"$run_label"
done
```

## Startup-to-synced

Startup uses the same scalar runner with explicit native package/patterns.
Its case IDs describe [chain placement](reproducibility.md#startup-chain-dataset),
independently of read sizes. Use the [startup timing
contract](methodology.md#chain-synchronization) and the shared environment table.
The [completed comparison](start_to_synced.md) links to the full collection's
source, samples, exclusions and profile evidence.
Only the selected smoke/reuse milestone is authorized during implementation;
full preparation, all cases and profiles need explicit run approval.

```sh
# Run one fresh SQLite lifecycle; repeating this command reuses saved fixtures.
BENCH_PACKAGE=./wallet/bench \
BENCH_CASE='^BenchmarkStartToSyncedSQLite$/^smoke$' \
  make bench method=start-to-synced db=sqlite case=smoke duration=1x \
  out=/tmp/btcwallet-bench/startup-pilot
```

Native kvdb selection uses package `./wallet` with
`^BenchmarkStartToSynced$/^smoke$/^Legacy$` or
`^BenchmarkStartToSynced$/^smoke$/^KVDB$`. PostgreSQL uses `./wallet/bench`
with `^BenchmarkStartToSyncedPostgres$/^smoke$`. Set the matching scalar db.
For approved full runs, replace the anchored smoke case and scalar case ID
with `empty`, `hits-0`, `hits-1`, `small-node` or `hits-100`. Startup has no collection shortcut;
run explicit cases serially in the shared balanced order. Use separate output
roots to preserve each independent 1x observation and its exact command/log.

```sh
# Only after profile approval, capture one prepared startup independently.
BENCH_PACKAGE=./wallet/bench \
BENCH_CASE='^BenchmarkStartToSyncedSQLite$/^small-node$' \
  make bench method=start-to-synced db=sqlite case=small-node \
  profile=cpu duration=1x out=/tmp/btcwallet-bench/startup-profiles
```

Use profile=mem in another invocation for the heap capture. Do not combine
profiling with timing samples or interpret the pilot as a full result table.
