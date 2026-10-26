# Benchmark reproducibility

This document records concrete settings, schedules, artifacts and saved data.
The [methodology](methodology.md) explains their interpretation. The
[shared commands](README.md) give the entrypoint. Collection evidence gives
actual run identity and execution details. The completed lnd observation below
establishes the model. Later methods reuse its data.

## Docker environment

The recorded measurements use Docker 29.6.2 and `linux/arm64` on the same host.
Docker fixes the client and server software and resource limits. Host load and
hardware still affect results. See the
[serial sampling rationale](methodology.md#serial-samples-and-aggregation).

| Component | Image and settings |
| --- | --- |
| Wallet client | `golang:1.25.11-bookworm`, 1 CPU, 4 GiB for reads or 16 GiB for start-to-synced, no swap, GOMAXPROCS=1, CGO=0, `-buildvcs=false -trimpath -p=1`. |
| Bitcoin Core (startup only) | `lightninglabs/bitcoin-core:30`, version 30.2, digest `sha256:844f2a308e243ce3aa3df7918bd2fe230259419280f7826a62b896510ad3dcbd`, 1 CPU, 12 GiB, no swap, regtest, `-disablewallet -txindex -blockfilterindex=1 -mocktime=2100000000`, RPC/ZMQ. |
| PostgreSQL | `postgres:18-alpine`, version 18.4, 1 CPU, 1 GiB, bridge TCP, Testcontainers `fsync=off`. |
| SQLite | Embedded in the client, WAL, foreign keys, 5s busy timeout. The two SQL pools use the usual 25-connection limit. |

The runner in `scripts/benchmark.sh` pins the client digest to
`sha256:b96f24a8d7d010ea0acb9c3ba99064740f02b6b984612b28bd3c9c5ab9453e38`.
The [SQL setup](../../../wallet/bench/setup_test.go) pins the server digest to
`sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15`.
The runner contains the full Docker invocation. Source is read-only.
Database storage is inside the Docker VM. Build and module caches use
`/tmp/go-build-cache/benchmark` on the host.

## Run and repeat

Run from the repository root with Docker available. Make its socket available
for PostgreSQL Testcontainers. These read fixtures use no live Bitcoin node.
The SQL setup uses the existing chain mock. Saved history supplies the query's
confirmed tip. Use the [shared commands](README.md) for explicit native
selection or installed friendly selectors.

Develop with the default `smoke` case and one backend. Select full datasets
only after code review and run approval. Use the [report
template](template.md) for API records. Their measured source revision(s)
identify the executed code. Implementations can use different revisions.

## Serial schedule and collection record

The symbol key is L=legacy kvdb, K=maintained kvdb, P=PostgreSQL and S=SQLite.
The current driver's four-backend unprofiled `db=all` schedule is:

`LKPS KPSL PSLK SLKP PKLS KLSP LSPK SPKL`

With all benchmarks available, each backend appears in each position two times.
Use friendly selectors only with installed native consumers. Explicit
package/pattern inputs retain their chosen entrypoint. This driver policy does
not reconstruct the history of a retained collection.

Retained three-backend measurements used:

`KPS KPS PSK SKP PKS KSP SPK SPK`

Those positions are not balanced. Added legacy samples use separate `L` runs.
Do not describe these reused groups and later legacy samples as one balanced
four-backend collection. Evidence records their actual commands
and groups. Do not infer the command's selection mode from its backend label.

Retained large-node ListAddresses is a separate single-call diagnostic in
`PSK` order. The legacy diagnostic uses a separate collection. It has no
profiles and is not part of the repeated-read median groups.

Smoke defaults to `1x`. Full reads default to a `3s` target, not a hard
timeout or a guarantee that N is more than one. The current collection has
these exceptions:

| Method | Dataset | Timing policy |
| --- | --- | --- |
| ListAddresses | medium-node | `5x` |
| GetAddressInfo | large-node | `5x` |
| ListAddresses | large-node | Separate `1x` diagnostic per backend, no profiles |

Keep exceptions identifiable in the collection record. Examine actual counts
and policies in evidence. Do not use the default policy as the policy for all
results. Raw commands, dates, actual execution orders, run labels, source
hashes, accepted/excluded attempts and per-run exceptions belong in that
evidence. Do not repeat them as usual metadata in each API report.

## Persisted fixture reuse

The runner mounts the named volume `btcwallet-bench-fixtures` at `/fixtures`.
This volume stores data across methods and code revisions. On a miss, setup
creates and saves the selected dataset. On a hit, it restores private storage
without creation. Even the first invocation restores the saved snapshot before
it opens the measured Wallet. Do not delete the volume between performance
changes.

The source's fixture revision and SQL bootstrap/migration hash select
compatible data. Query text, executable identity and commit SHA do not.
See [preparation and storage](#prepare-and-save-data) for native snapshot paths.
Direct Go runs without `BTCWALLET_BENCH_FIXTURE_DIR` use temporary data instead.

Setup logs distinguish `fixture preparation` from `fixture restoration`.
Repeated commands should restore data without new preparation. Evidence keeps
snapshot hashes, sizes and modification times before and after reuse. Restore,
startup and cleanup still cost whole-command time. See the [measurement
boundary](methodology.md#timing-and-profiles).

## Artifacts and profiles

Each executed benchmark writes under
`<out>/<method>/<case>/<backend>/<timing|cpu|mem>/`.
Keep stdout/stderr for completed, failed and excluded invocations with their
run evidence. Diagnostic captures are separate from unprofiled timing output.

| Invocation | Files |
| --- | --- |
| All executed benchmarks | `benchmark.test` |
| CPU | `cpu.pprof` |
| Heap | `heap-before.pprof`, `heap-after.pprof` |

The benchmark captures the heap baseline after setup and the untimed first
API call.
Subtract `heap-before.pprof` from `heap-after.pprof` with `go tool pprof -base`.
Examine `alloc_space` for allocation traffic since the baseline and
`inuse_space` for the change in retained Go heap. The two snapshots use equal GC
handling. The runner prints the analysis after benchmark cleanup. See the
[profiling rationale](methodology.md#separate-profiling) for interpretation.

## Data source: an lnd node

The completed lnd integration test observed the funding node's btcwallet data.
The peer's wallet, lnd's channel database and the chain inventory were separate.
The reference scenario had these steps:

1. Fund a new wallet with one confirmed 1 BTC UTXO.
2. Open 100 public anchor channels to one peer. Each channel has 500,000 sat
   capacity and sends 100,000 sat to the peer. Complete all opens before any
   close. Each funding transaction spends the previous transaction's change.
3. Close 98 channels cooperatively. Keep their returned wallet funds.
4. Send ten outgoing HTLCs of 10,000 sat through each remaining channel.
   The peer holds them. The two channels keep positive local and remote
   balances.
   Force-close the two channels from the funding node.
5. Confirm commitments and advance CSV/CLTV maturity until the two resolutions
   finish. Let lnd select sweep batches and fee inputs. Record pending anchor
   sweeps separately.

The reference used a fixed fee estimate of 2,500 sat/kw and the harness's
usual confirmation and CSV settings. Settled payments do not create a wallet
transaction or a new ordinary address for each payment. The scenario omits
these payments.

The experiment captured account, address, transaction, UTXO and pending-output
RPC responses after the deposit, channel opens and channel closes. It included
custom key accounts. It stopped the wallet and read a database copy through
the address manager. It counted persisted addresses and their used flags.
It counted imported pseudo-accounts separately from regular scoped accounts.

Channel keys use scope `1017` and separate key-family accounts. Key derivation
advances each index. Use inside a channel contract does not mark the key's
ordinary address as used.

`ListUnspent` walks unspent outputs and finds their owning addresses. It does
not enumerate all unused channel keys. Separate accounts and branches keep
channel keys out of ordinary address discovery. Broader load and rescan
operations can still read these records.

### Observed reference

The reference passed on 2026-10-23. The lifecycle took 12m 19s. The whole test
took 12m 23s and mined 731 blocks. This native macOS arm64 experiment used
Go 1.27.3. It established data shape, not Docker API latency.

The local experiment commit is
`804ac54201c40adb1466617dba9676f6307bfc9d`, based on lnd
`1a359d4aa1e58daad2c3c5ade1ff3f415f91ac1b`. It used btcwallet
`16cfb4483d1f618bae04dbe9206584bf4ee2e72d` and btcd v0.26.0.
The experiment is not in upstream lnd. These commands identify the completed
reference run and require that checkout. Normal benchmark runs use the saved
model data below. They do not run this lnd experiment again.

```sh
# Build the experiment harness and keep its raw RPC data and stopped snapshots.
export GOTOOLCHAIN=go1.27.3
export LND_WALLET_REFERENCE_DIR=/absolute/path/to/reference-output
make build-itest backend=btcd GOCC=/opt/homebrew/opt/go/bin/go
# Select only the one-deposit channel scenario in the prepared harness.
make itest-only backend=btcd dbbackend=bbolt \
  icase=wallet_channel_reference timeout=30m GOCC=/opt/homebrew/opt/go/bin/go
```

| Funding wallet data | Funded | 100 channels open | Closes resolved |
| --- | ---: | ---: | ---: |
| Regular scoped accounts | 260 | 260 | 260 |
| Accounts with address/key records | 1 | 8 | 8 |
| Ordinary addresses | 1 | 101 | 203 |
| Ordinary addresses marked used | 1 | 101 | 202 |
| Channel keys, all unmarked as used | 0 | 601 | 601 |
| Wallet transaction records | 1 | 101 | 204 |
| Confirmed spendable UTXOs | 1 | 1 | 101 |

The 260 accounts contain four ordinary default accounts and 256 scope-1017
accounts. Five imported pseudo-accounts are separate. The final address
inventory has one BIP84 receiving address, 100 BIP86 change addresses and
102 BIP86 external addresses. Key families 0–4 each have 100 keys. Family 5
has 101 because lnd skips its first revocation-root index.

The 204 records contain one deposit, 100 funding transactions, 100 closes
and three sweeps. The RPC gives positive confirmations for 202 records.
Its two force-close records still have zero confirmations after resolution.

The sweeper combines the two local balances. It combines 20 HTLC timeout inputs
with one cooperative-close output for fees. It then sweeps the 20 second-stage
outputs together. One HTLC does not imply one independent wallet transaction.

The final 101 UTXOs are P2TR outputs: one funding-change output, 97 cooperative
returns and three sweep outputs. Their total value is 89,636,054 sat.
No channel resolution is pending. Two uneconomical 330-sat anchor sweeps
stay pending. They are not part of the spendable output count.

## Shared node datasets

The [case builder](../../../wallet/internal/bwtest/bench_cases.go) models this
history with deterministic unsigned transactions and foreign contracts.
A shared fixed seed gives each backend the same account paths and scripts.
The builder keeps transaction links, credit ownership, values and script types.
It does not sign channels or import lnd's channel database.

Positive confirmation heights are dense. Each deposit's history has two
unconfirmed force-close bookkeeping records. All ordinary credits at the
endpoint are confirmed. Each deposit leaves one unused ordinary address.
All channel keys stay unused.

These choices normalize the reference data. They do not reproduce its full
block schedule.

### small-node

This case models the observed one-deposit history.

| Parameter | Value |
| --- | --- |
| Initial deposits | 1 UTXO, 1 BTC |
| Channels | 100: 98 cooperative closes, 2 force closes |
| Pending HTLCs at force close | 20 |
| Regular scoped accounts | 260 |
| Ordinary addresses | 203 |
| Channel keys | 601 |
| Wallet transaction records | 204 |
| Final confirmed tip | 202 |
| Final spendable P2TR outputs | 101 |
| Final owned value | 89,636,054 sat |

### medium-node

This model repeats the normalized history for ten independent deposits in
one Wallet. Accounts stay fixed. Addresses, keys and transaction links are
different across deposits.

| Parameter | Value |
| --- | --- |
| Initial deposits | 10 UTXOs, 10 BTC |
| Channels | 1,000: 980 cooperative closes, 20 force closes |
| Pending HTLCs at force close | 200 |
| Regular scoped accounts | 260 |
| Ordinary addresses | 2,030 |
| Channel keys | 6,001 |
| Wallet transaction records | 2,040 |
| Final confirmed tip | 2,020 |
| Final spendable P2TR outputs | 1,010 |
| Final owned value | 896,360,540 sat |

### large-node

This model repeats the history for 100 deposits in one Wallet.

| Parameter | Value |
| --- | --- |
| Initial deposits | 100 UTXOs, 100 BTC |
| Channels | 10,000: 9,800 cooperative closes, 200 force closes |
| Pending HTLCs at force close | 2,000 |
| Regular scoped accounts | 260 |
| Ordinary addresses | 20,300 |
| Channel keys | 60,001 |
| Wallet transaction records | 20,400 |
| Final confirmed tip | 20,200 |
| Final spendable P2TR outputs | 10,100 |
| Final owned value | 8,963,605,400 sat |

Each added deposit needs one BIP84 receiving address, 100 BIP86 change
addresses and 102 BIP86 closing/sweep addresses. Each key family gains 100 keys.
Family 5 skips index zero one time per Wallet. Transaction hashes, outpoints,
foreign contracts and positive block metadata stay different. Received times
stay ordered across deposits.

The model repeats three resolution transactions per deposit. Real lnd can
combine sweeps across histories, select other fee inputs or consolidate funds.
Its final counts can be different. The lnd experiment observed only the
one-deposit origin.

The names describe model sizes, not measured user populations. Related data
grows together. These cases do not isolate the cost of live UTXO count.

The `smoke` development case uses one deposit and 20 channels. It has the same
260 accounts, with 43 ordinary addresses, 121 channel keys, 44 transaction
records and 21 final UTXOs. Use it for fast development checks.

## Prepare and save data

The shared [SQL setup](../../../wallet/bench/setup_test.go) prepares common
node data. It uses Manager to create and unlock the Wallet. It creates
ordinary and internal accounts through public APIs. It allocates ordinary
addresses in bulk and internal keys through the public key allocator. A
separate Store writes the full transaction history through `ApplyTxBatch`.

The [kvdb setup](../../../wallet/benchmark_helpers_test.go) uses its
native Manager and scoped address manager. Its shared seeder derives addresses
in bulk and applies history through Store, with confirmed-tip progression.
The two suites must consume the same case definition. Legacy and maintained kvdb
share one saved database per size. SQL preparation does not call the kvdb suite.

Before you save data, close all database users. Save kvdb and SQLite as closed
files. Save PostgreSQL with a custom-format `pg_dump` archive. Restore a
private copy before each invocation, even the first. The measured Wallet does
not use seed-process caches. Keep prepared data for all benchmark methods.

Before Wallet startup, make an analysis of each private PostgreSQL restore
to give the planner column statistics. This work is outside timing. Reuse the
saved archive without new data preparation.

The Docker volume uses `lnd-wallet/v1/kvdb/<case>.db` for kvdb.
SQL uses `lnd-wallet/v1/<schema-hash>/<backend>/<case>.db`, where the backend is
`sqlite` or `postgres`. The schema hash covers bootstrap and migration files.
Reuse this base when executable or query code changes. Rebuild only when
fixture inputs, seed behavior or storage compatibility change.

### Preparation measurements

These Docker observations date from 2026-10-23. The one-deposit source was
`963f383a18061961088480994cfbb6bef52d065d`. The ten- and hundred-deposit source
was `1883b5cb2caa8d5b904a6599bf1d3ec091ec8a6b`. These source IDs identify the
actual preparation runs.

Preparation includes Wallet creation, data writes, closure and snapshot save.
Restore measures only file copy or `pg_restore`. Whole-command time also
includes build, startup, one API call and cleanup. These one-call observations
are not API latency results. The saved files kept the same hash, size and
modification time after reuse. Saved runs did no seed work.

#### small-node preparation

| Storage | Prepare | Accounts | Addresses/keys | History | Restore | First command | Reused command |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| kvdb | 1.845s | 0.378s | 1.358s | 0.094s | 0.54–0.61ms | 11.47s | 3.06–3.21s |
| SQLite | 3.172s | 2.324s | 0.684s | 0.127s | 0.31ms | 7.21s | 3.40s |
| PostgreSQL | 3.661s | 2.367s | 0.732s | 0.343s | 147.69ms | 9.04s | 4.86s |

#### medium-node preparation

| Storage | Prepare | Accounts | Addresses/keys | History | Restore | First command | Reused command |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| kvdb | 15.870s | 0.390s | 14.104s | 1.356s | 3.41–3.53ms | 21.42s | 3.21–4.37s |
| SQLite | 14.607s | 2.361s | 7.842s | 4.364s | 1.81ms | 18.26s | 3.57s |
| PostgreSQL | 16.561s | 2.387s | 7.462s | 6.374s | 283.49ms | 21.77s | 5.03s |

#### large-node preparation

These observations measure data preparation only. They do not measure API
latency. Each method record gives its API measurements.

| Storage | Prepare | Accounts | Addresses/keys | History | Restore | First command | Reused command |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| kvdb | 2m37.7s | 0.396s | 136.475s | 20.756s | 23.21–23.38ms | 174.45s | 5.96–16.75s |
| SQLite | 9m13.5s | 2.377s | 85.762s | 465.255s | 14.80ms | 557.21s | 3.41s |
| PostgreSQL | 7m22.6s | 2.439s | 75.541s | 363.573s | 1.046s | 448.73s | 5.97s |

SQL's account phase includes Wallet creation and unlock. Kvdb includes those
costs in the total. The 16 larger preparation/reuse invocations took 21m 39s
of whole-command time. These costs belong to data preparation, which later
measurements avoid through saved reuse.

## Startup chain dataset

Startup uses the same small-node Wallet model with a separate chain placement.
Every case starts with one unfunded Wallet: 260 regular accounts, 203 ordinary
addresses and 601 channel keys, the seed/birthday above and zero recovery
lookahead. Keys already exist; a new or unfunded Wallet is not an empty
metadata database. Ordinary receiving uses BIP84; change and closing addresses
use BIP86. Internal channel-key families remain separate and unused as payment
addresses. Backend-specific native allocation is reused without ApplyTxBatch.

The nonzero cases use the same 204-transaction graph: one deposit, 100 openings,
98 cooperative closes, two force closes and three sweeps. Shapes are 1-to-2
openings/cooperative closes, 1-to-14 commitments, a 2-to-1 balance sweep,
21-to-21 timeout/fee transaction and 20-to-1 final sweep. Owned scripts, amounts,
ancestry and the expected 101 spendable outputs follow the shared model.
The two foreign-only force parents need not appear as discovered Wallet
records. See the [interpretation](methodology.md#chain-synchronization).

| Startup case | Catch-up blocks | Background tx/block | Blocks with Wallet matches | Wallet graph tx |
| --- | ---: | ---: | --- | ---: |
| smoke | 10 | 6,000 | 5 | 204 |
| empty | 1,000 | 0 | none | 0 |
| hits-0 | 1,000 | 6,000 | none | 0 |
| hits-1 | 1,000 | 6,000 | 500 | 204 |
| small-node | 1,000 | 6,000 | 100,200,...,1,000 | 204 |
| hits-100 | 1,000 | 6,000 | 10,20,...,1,000 | 204 |

The three full nonzero ratios are 0.1%, 1% and 10% of blocks containing actual
Wallet matches. They are not Wallet fractions of all transactions or counts
of positive compact filters. Graph index i, starting at zero, is assigned to
occupied block floor(i*H/204), interpreted as an index into the explicit H
occupied heights. Keep parent-before-child order within a block. Foreign-only
parents do not by themselves count as Wallet matches. Empty schedules still
prepare all requested blocks; nil history is not a target-cache hit.

Each unrelated transaction spends one miner P2WPKH input to a distinct tagged
foreign P2WSH recipient and P2WPKH miner change. It pays 1,000 sat with a
1,000 sat fee. Six thousand lanes roll change forward independently; only the
prior background block is retained during preparation. Estimated background
payload is about 3.6..3.7 million weight units and 1.4 MB per block. Actual
mined block data belongs in run evidence, separately from these estimates.

Calibration uses mainnet blocks 973169..973183, obtained from the
[fixed-height metadata endpoint](https://mempool.space/api/v1/blocks/973183).
Their 2,237..7,783 transactions occupy about 3.993..3.998 million weight units;
median serialized size is 1,584,601 bytes. Raw examples at heights 973183,
973182 and 973171 were inspected against their header hashes, byte counts and
weights. This is a small reference window, not a universal traffic estimate.
The controlled single-template background approximates payload and scan load;
it does not reproduce mainnet input/output, witness, script or OP_RETURN mixes.

The observed lnd lifecycle occupied 731 blocks: deposit 439, openings 440+6*i,
cooperative closes 1040..1137, both force parents 1138, balance sweep 1142,
timeout/fee 1165 and final sweep 1169. The controlled placements compress that
schedule, including same-block ancestry. Tagged foreign witnesses replace
Lightning CSV/CLTV contracts while preserving P2WSH type and distinctness.
Their script/witness sizes differ from real Lightning contracts. This is a
chain-valid shape model, not an lnd protocol replay or mainnet archive replay.
Disclose these differences and inspect the pilot before scaling.

### Prepare and reuse the startup fixture

Mine 103 maturity blocks with the fixed preparation miner. Coinbase one funds
the Wallet deposit. Mature coinbases two through four fund one 6,000-output
P2WPKH fan-out at height 104. Their 150 BTC permits each lane to pay 2,000 sat
per block throughout 1,000 blocks. Save the stopped common base 104, including
this fan-out, even for the empty control. Its exact hash is retained in logs.
Every native Wallet baseline synchronizes to this exact base before shutdown.

After Wallet shutdown, mine the case's explicit ordered transactions through
real Core generateblock. Core validates and submits each block. There is no
mempool-throughput measurement or synthetic database ingestion. Full targets
end at 1104; smoke ends at 114. Save the closed target before publishing each
closed native Wallet baseline. Independent targets have their own hashes.
The smoke contains 60,000 background and 204 Wallet graph transactions; each
populated full target contains 6,000,000 background transactions and, when
nonzero, 204 Wallet graph transactions. Coinbase and base funding are separate.

The volume namespace is `start-to-synced/v2/bitcoin-30.2`. Common base is
`chain/base`; targets are `chain/<case>/target`. Kvdb baselines use
`kvdb/<case>.db`; SQL uses `<schema-hash>/<backend>/<case>.db`. The case ID is
separate from fixed Wallet model ID. Reuse across executable changes; read
fixtures and old startup-v1 evidence remain separate. Restores are private
closed files/directories, or the existing PostgreSQL dump/restore mechanism.
A missing target is published even for zero-history cases.

Untimed native and SQL preparation allow 20 minutes; measured samples retain
30 minutes and the outer startup command retains one hour. The first full
hits-0 attempt at `ff8ac2997bb64e0b41e82a0216d66651ee0099fb` exhausted the
former ten-minute preparation context. It supplied no sync metric or recorded
OOM event; its 619.103s whole-command duration is a failed preparation outcome.

Use the resource table above for every implementation in this cohort. The
Docker VM allocation was increased to 32 GB before collection. Old startup
observations used smaller container limits and a different dense chain;
retain their provenance and exclusions rather than pooling them with v2.
Two selected SQLite smoke invocations establish real-chain validity and
persistent reuse. Inspect the closed target block file separately to record
actual weights, bytes, counts and placement; add no benchmark validation reads.
They do not establish the capacity of a 1,000-block batch. After separate full
run approval, begin with one hits-0 target and one maintained SQLite 1x sample,
recording preparation time and exact deadline/OOM outcome. Continue an approved
matrix only after that succeeds. A resource or deadline failure requires a
replan before changing payload, limits, modes or existing preparation timeout.

### Startup pilot observations

The two selected SQLite smoke invocations on 2026-10-26 measured source
`f993b2ea8c94bcb7d78a069a5e3466e76b6bbd54`. They used identical binaries,
SHA256 `6c4f82c8403d22f2461d274e9cb17d7169e85c6bfa9cc0e1f1f1fd0737b79ac9`.
These are development observations, not the full comparison result.

| Invocation | ns/op | B/op | allocs/op | Whole command |
| --- | ---: | ---: | ---: | ---: |
| Initial preparation | 1,095,287,584 | 374,081,184 | 1,910,174 | 20.047s |
| Persistent reuse | 1,089,946,168 | 378,279,024 | 1,907,960 | 6.781s |

All 64 saved fixture files kept identical checksums after reuse, which logged
restoration without allocation/mining. Both invocations completed at height 114,
hash `3b86f077c7d8476b5a42aaf0ab299f9cdad04918ae7e888b51e1c7b473c16ea6`.
The common base 104 hash is
`2d95ea58f90bb55d546d4e6c56a7c57884b275799aeaebf969798993e7d452f5`.

Standalone inspection of the closed target block file found exactly 60,000
background transactions and 204 graph transactions. Offset 5 (height 109) has
6,205 transactions including coinbase, of which 202 have modeled Wallet credits.
Other catch-up blocks each have 6,001 transactions including coinbase.
Their sizes are 1,407,205..1,407,278 bytes and weights 3,657,850..3,657,923 WU.
The matching block is 1,451,049 bytes and 3,795,684 WU, including the graph.
These observations confirm the selected payload fits individual valid blocks;
they do not establish 1,000-block batch capacity. Raw command receipts, immutable
fixture checksums and block-inspection.json are retained under the task-local
`.lgtm/task-sync-bench/runs/chain-v2/` evidence directory. No full cases or
profiles were collected for this cohort.
