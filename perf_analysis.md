# `utxos.wallet_id` Performance Analysis

## Scope

This report compares two schema variants for `utxos`:

- **A**: keep `utxos.wallet_id`
- **B**: drop `utxos.wallet_id` and derive wallet ownership from `transactions.wallet_id`

The goal here is strictly to understand the performance impact of `utxos.wallet_id` under realistic workloads. Integrity tradeoffs are noted briefly, but the focus of this document is query and storage behavior.

## Harness And Method

- Analysis branch/worktree: `perf/utxo-walletid-analysis`
- Harness entrypoint: `wallet/internal/db/cmd/utxo_walletid_analysis/main.go`
- Postgres runner: `wallet/internal/db/cmd/utxo_walletid_analysis/postgres_runner.go`
- SQLite runner: `wallet/internal/db/cmd/utxo_walletid_analysis/sqlite_runner.go`
- Benchmark result sources:
  - `/tmp/utxo_walletid_two_wallets_100k_5_r5.md`
  - `/tmp/utxo_walletid_sqlite_two_wallets_100k_5_r5.md`
  - `/tmp/utxo_walletid_both_1000_wallets_100tx_10_r5.md`

Benchmark rules:

- identical synthetic data is loaded into both variants
- B is not a naive schema drop; it gets fair replacement indexes
- hot queries measured:
  - `ListUtxos(wallet)`
  - `ListUtxos(account)`
  - `Balance`
  - `GetUtxoByOutpoint`
  - `GetUtxoIDByOutpoint`
  - `AcquireUtxoLease`
  - `ReleaseUtxoLease`
  - `InsertTx+Credits`
  - `MarkUtxoSpent`
  - `ClearUtxosSpentByTxID`
  - `DeleteUtxosByTxID`
- storage measured from table and index footprints

Engine-specific notes:

- **Postgres**: `A exec ms` and `B exec ms` come from `EXPLAIN (ANALYZE, BUFFERS)` server-side execution time; `p50` is end-to-end client timing over repeated runs.
- **SQLite**: `A exec ms` and `B exec ms` are single timed executions; index names come from `EXPLAIN QUERY PLAN` details.

## Schema Summary

### Variant A

- `utxos.wallet_id` is stored explicitly
- wallet-scoped joins use `(wallet_id, tx_id)`
- wallet-scoped uniqueness and FKs live directly on `utxos`

### Variant B

- `utxos.wallet_id` is removed
- wallet ownership is derived from `transactions.wallet_id`
- fair replacement indexes are added, notably wallet-first support on live transactions

In B, the critical broad-read shape becomes:

```sql
FROM utxos AS u
INNER JOIN transactions AS t ON u.tx_id = t.id
...
WHERE t.wallet_id = ?
```

instead of A's direct UTXO wallet filter:

```sql
FROM utxos AS u
INNER JOIN transactions AS t
    ON u.wallet_id = t.wallet_id AND u.tx_id = t.id
...
WHERE u.wallet_id = ?
```

## Workload 1: 2 Wallets, 100k Tx Per Wallet, 5 UTXOs Per Tx

Dataset shape:

- 2 wallets total
- 100,000 transactions per wallet
- 5 outputs per transaction
- 1,000,000 total UTXO rows

### Postgres

Key numbers:

| Query | A exec ms | B exec ms | Outcome |
| --- | ---: | ---: | --- |
| `ListUtxos(wallet)` | 275.01 | 323.23 | A faster by ~17% |
| `ListUtxos(account)` | 123.04 | 122.72 | tie |
| `Balance` | 320.54 | 301.15 | B faster by ~6% |
| `GetUtxoByOutpoint` | 0.10 | 0.10 | tie/slight A |
| `GetUtxoIDByOutpoint` | 0.05 | 0.06 | slight A |
| `AcquireUtxoLease` | 0.50 | 0.74 | A faster |
| `InsertTx+Credits` | 0.33 | 0.34 | tie |
| `MarkUtxoSpent` | 0.23 | 0.19 | slight B |
| `ClearUtxosSpentByTxID` | 0.24 | 0.17 | B faster |
| `DeleteUtxosByTxID` | 0.19 | 0.15 | B faster |

Storage:

- A database size: `333.77 MiB`
- B database size: `277.67 MiB`
- B saves about `56.10 MiB` total, or roughly `16.8%`

Largest storage deltas:

- `utxos`: `239.71 MiB` -> `177.76 MiB` (`-61.95 MiB`)
- `idx_utxos_unspent`: `37.85 MiB` -> `22.96 MiB` (`-14.89 MiB`)
- `idx_utxos_by_tx`: `12.99 MiB` -> `11.22 MiB` (`-1.77 MiB`)
- `transactions` grows in B because of `idx_transactions_live_by_wallet`: `+6.03 MiB`

Query-plan interpretation:

- This is the main workload where A shows a real read advantage on Postgres.
- With only 2 very large wallets, `u.wallet_id = $1` is still materially selective: it cuts the candidate UTXO space roughly in half before the rest of the joins matter.
- `ListUtxos(wallet)` is the main beneficiary of that direct wallet filter.
- `Balance` does not benefit as much from A because B's smaller `utxos` heap and smaller UTXO-side indexes help the aggregate path.
- Point lookups are almost identical because both variants still resolve the outpoint through wallet-scoped `transactions` first.

Bottom line for this workload:

- If the dominant query is `ListUtxos(wallet)` on Postgres and the system only has a few very large wallets, A has a measurable upside.
- Outside of that query, B is equal or slightly better while still being meaningfully smaller on disk.

### SQLite

Key numbers:

| Query | A exec ms | B exec ms | Outcome |
| --- | ---: | ---: | --- |
| `ListUtxos(wallet)` | 2151.69 | 725.33 | B faster by ~66% |
| `ListUtxos(account)` | 489.59 | 277.33 | B faster by ~43% |
| `Balance` | 2255.29 | 336.56 | B faster by ~85% |
| `GetUtxoByOutpoint` | 0.18 | 0.22 | slight A |
| `GetUtxoIDByOutpoint` | 0.08 | 0.06 | slight B |
| `AcquireUtxoLease` | 0.16 | 0.12 | slight B |
| `InsertTx+Credits` | 2.49 | 1.27 | B faster |
| `MarkUtxoSpent` | 0.06 | 0.05 | slight B |
| `ClearUtxosSpentByTxID` | 0.08 | 0.07 | slight B |
| `DeleteUtxosByTxID` | 0.10 | 0.07 | B faster |

Storage:

- A database size: `167.94 MiB`
- B database size: `144.85 MiB`
- B saves about `23.09 MiB`, or roughly `13.7%`

Plan-pattern interpretation from `EXPLAIN QUERY PLAN`:

- A broad reads used address/account-side paths such as `idx_accounts_scope` and `idx_utxos_by_address`.
- B broad reads used a cleaner wallet-first transaction path: `idx_transactions_live_by_wallet` plus `idx_utxos_by_tx`.
- On SQLite, that planner shape is dramatically better for the broad wallet reads than keeping wallet info on `utxos`.

Bottom line for this workload:

- On SQLite, B is decisively better for all broad reads that matter.
- This is not a marginal difference; `ListUtxos` and `Balance` are several times faster in B.

## Workload 2: 1000 Wallets, 100 Tx Per Wallet, 10 UTXOs Per Tx

Dataset shape:

- 1000 wallets total
- 100 transactions per wallet
- 10 outputs per transaction
- 1,000,000 total UTXO rows

### Postgres

Key numbers:

| Query | A exec ms | B exec ms | Outcome |
| --- | ---: | ---: | --- |
| `ListUtxos(wallet)` | 2.37 | 1.68 | B faster by ~29% |
| `ListUtxos(account)` | 0.68 | 0.66 | tie |
| `Balance` | 2.36 | 0.81 | B faster by ~66% |
| `GetUtxoByOutpoint` | 0.11 | 0.13 | slight A |
| `GetUtxoIDByOutpoint` | 0.04 | 0.05 | slight A |
| `AcquireUtxoLease` | 0.36 | 0.35 | tie |
| `InsertTx+Credits` | 0.37 | 0.23 | B faster |
| `MarkUtxoSpent` | 0.17 | 0.14 | B faster |
| `ClearUtxosSpentByTxID` | 0.17 | 0.13 | B faster |
| `DeleteUtxosByTxID` | 0.17 | 0.16 | B faster |

Storage:

- A database size: `560.20 MiB`
- B database size: `512.77 MiB`
- B saves about `47.43 MiB`, or roughly `8.5%`

Largest storage deltas:

- `utxos`: `245.20 MiB` -> `194.57 MiB` (`-50.63 MiB`)
- `idx_utxos_unspent`: `28.41 MiB` -> `23.54 MiB` (`-4.88 MiB`)
- `transactions` grows by `+3.03 MiB` due to `idx_transactions_live_by_wallet`

Query-plan interpretation:

- This workload strongly favors B.
- With 1000 wallets, `t.wallet_id = $1` is extremely selective. Starting from wallet-scoped transactions and then joining to `utxos` by `tx_id` is efficient.
- At the same time, A still carries a larger UTXO row and larger UTXO indexes, so the direct `u.wallet_id` filter no longer compensates for the extra width.
- `Balance` benefits even more than `ListUtxos(wallet)` because the aggregate can exploit B's narrower `utxos` footprint and wallet-first transaction path.

Bottom line for this workload:

- When the database holds many wallets, B is the clearly better Postgres design for the broad wallet-scoped reads.

### SQLite

Key numbers:

| Query | A exec ms | B exec ms | Outcome |
| --- | ---: | ---: | --- |
| `ListUtxos(wallet)` | 2.49 | 1.39 | B faster by ~44% |
| `ListUtxos(account)` | 1.55 | 0.68 | B faster by ~56% |
| `Balance` | 2.11 | 0.73 | B faster by ~65% |
| `GetUtxoByOutpoint` | 0.12 | 0.10 | slight B |
| `GetUtxoIDByOutpoint` | 0.09 | 0.06 | B faster |
| `AcquireUtxoLease` | 0.16 | 0.10 | B faster |
| `InsertTx+Credits` | 0.26 | 0.27 | tie |
| `MarkUtxoSpent` | 0.05 | 0.06 | slight A |
| `ClearUtxosSpentByTxID` | 0.07 | 0.06 | slight B |
| `DeleteUtxosByTxID` | 0.09 | 0.07 | B faster |

Storage:

- A database size: `287.50 MiB`
- B database size: `259.52 MiB`
- B saves about `27.98 MiB`, or roughly `9.7%`

Plan-pattern interpretation:

- SQLite again favors the wallet-first transaction path in B.
- `EXPLAIN QUERY PLAN` shows B leaning on `idx_transactions_live_by_wallet` and `idx_utxos_by_tx` for the broad wallet reads.
- A again tends to route the broad reads through less direct UTXO/address-side access paths.

Bottom line for this workload:

- B is consistently better in SQLite for the broad reads and most maintenance operations.

## Cross-Workload Findings

### What `utxos.wallet_id` helps

- A can help **Postgres `ListUtxos(wallet)`** when there are only a few very large wallets, because `u.wallet_id = $1` is still selective enough to be useful.
- A remains slightly better or tied for some point lookups and some lease paths, but those differences are tiny and sub-ms.

### What `utxos.wallet_id` does not reliably help

- A does **not** produce a universal read win.
- In workloads with many wallets, B is better on Postgres and SQLite for the broad reads that matter most.
- On SQLite, A was not the better design in any broad-read workload tested.

### What B consistently improves

- smaller `utxos` rows
- smaller UTXO-side indexes
- lower total storage footprint
- usually better `Balance`
- usually better write-maintenance operations (`MarkUtxoSpent`, `ClearUtxosSpentByTxID`, `DeleteUtxosByTxID`)

### Most Important Performance Takeaway

The evidence does **not** support keeping `utxos.wallet_id` for general performance reasons.

The actual picture is:

- **Postgres, few huge wallets**: A may help `ListUtxos(wallet)`
- **Postgres, many wallets**: B is better overall
- **SQLite, both tested workloads**: B is clearly better overall

So if `utxos.wallet_id` is retained, the strongest argument is not raw speed. The strongest argument is DB-enforced wallet-scoping integrity.

## Integrity Footnote

Although this report focuses on performance, the repeated integrity checks were stable across engines:

- A rejects cross-wallet `spent_by_tx_id` links
- A rejects cross-wallet lease-to-UTXO mismatches
- B allows both unless query logic or triggers enforce them

Neither A nor B fully enforces `address_id` wallet ownership at the schema level today, because `addresses` does not carry `wallet_id`.

## Recommendation From The Performance Data Alone

If performance is the only dimension:

- **SQLite**: prefer **B**
- **Postgres**: prefer **B** in general, unless the primary workload is specifically a small number of very large wallets and `ListUtxos(wallet)` dominates enough to justify the tradeoff

If the project keeps `utxos.wallet_id`, it should be described as an **integrity-first design choice**, not as an across-the-board performance optimization.

## Rerun Commands

```bash
GOWORK=off go run ./wallet/internal/db/cmd/utxo_walletid_analysis -engine postgres -scale two-wallets-100k-5 -repeats 5 -warmups 1
GOWORK=off go run ./wallet/internal/db/cmd/utxo_walletid_analysis -engine sqlite -scale two-wallets-100k-5 -repeats 5 -warmups 1
GOWORK=off go run ./wallet/internal/db/cmd/utxo_walletid_analysis -engine both -scale 1000-wallets-100tx-10 -repeats 5 -warmups 1
```
