# Benchmarks

Use shared node datasets for Wallet read benchmarks. Prepare each dataset
once per backend and fixture revision. Reuse saved data across methods and
performance changes. Chain sync and startup need separate lifecycle benchmarks.

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
the corresponding benchmark consumer is present. Explicit `BENCH_PACKAGE`
and `BENCH_CASE` inputs take precedence and must be supplied together.
They select one scalar leaf; collection shortcuts require friendly selectors.

Select `legacy`, `kvdb`, `sqlite` or `postgres` for one implementation.
Friendly selectors select the installed native counterparts for each backend.
Explicit package/pattern inputs take precedence over friendly mapping.
Native request semantics and the chosen comparison baseline belong in each API
report. The original kvdb comparison matrices remain available.

During development, use one affected backend and the default `smoke` case.
Use unit tests for correctness. Complete code review and get run approval
before full preparation or measurement.

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

Keep each invocation's raw command and output in its run evidence. Follow the
[report template](template.md) when writing the API record.

## Collect profiles

Use one backend/case, or `db=all` and `profile=all` for available leaves.
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
