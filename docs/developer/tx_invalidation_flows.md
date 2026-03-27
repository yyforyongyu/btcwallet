# Transaction Invalidation Flows

This document defines the transaction-invalidation event model used by the SQL wallet store. It complements [Wallet Data Model and Lifecycle](./utxo_data_model.md), which defines the state model, and [ADR 0006: Wallet Transaction Manager SQL Schema](./adr/0006-wtxmgr-sql-schema.md), which defines the schema and its invariants.

The goal of this document is narrower: to explain which public tx-store methods represent wallet events, which lower-level graph transitions stay internal to each backend, and why each wallet event must be applied atomically.

## 1. Public Transaction Events

The public `TxStore` surface is event-shaped rather than graph-operation-shaped.

| Method | Event |
| --- | --- |
| `CreateTx` | Ingest one wallet-relevant transaction into history, with optional confirming block context. |
| `UpdateTx` | Patch one existing row's mutable metadata (`label`, `block`, `status`) without rewriting graph edges. |
| `DeleteTx` | Remove one user-selected unmined leaf transaction through the ordinary cleanup path. |
| `InvalidateUnminedTx` | Invalidate one wallet-owned unmined branch when it is no longer valid. |
| `RollbackToBlock` | Apply one rollback/reorg event at the block boundary. |

These methods describe what happened from the wallet's point of view. They do not expose backend-specific graph mechanics such as direct replacement victims, descendant walks, or root-only orphan reconfirmation.

## 2. Atomicity Rule

Each public transaction event must execute in one database transaction.

This matches the legacy `kvdb` behavior, where:

- transaction ingest runs inside one `walletdb.Update`
- unmined invalidation runs inside one `walletdb.Update`
- rollback runs inside one `walletdb.Update`

The SQL backends must preserve the same all-or-nothing boundary. A wallet event may touch transaction rows, UTXO spend edges, descendant branches, replacement edges, and wallet sync-state metadata, but none of those changes may commit partially.

## 3. Internal Graph Mechanics

The SQL store still needs lower-level graph workflows internally. Examples include:

- failing or replacing one direct conflict root set
- invalidating descendants of an already-invalid root
- orphaning disconnected coinbase roots during rollback
- restoring an orphaned coinbase row when the same coinbase re-enters the best chain

These remain backend-internal helpers. They are not the public store API because the wallet runtime does not think in those terms. The wallet reacts to higher-level events such as transaction ingress, publisher rejection, and rollback.

## 4. Method Responsibilities

### 4.1 `CreateTx`

`CreateTx` is the public transaction-ingest method.

It may internally:

- insert a new unmined row
- insert a new confirmed row
- confirm an already-known unmined row for the same transaction hash
- reconcile direct conflict branches that the newly ingested transaction supersedes

The method still preserves the invariant that callers do not insert derived invalid states directly. Replacement, failure, and orphaning remain internal consequences of transaction ingress rather than public API calls.

### 4.2 `UpdateTx`

`UpdateTx` is intentionally row-local.

It may patch:

- the user-visible label
- the stored block assignment
- the stored wallet-relative status

It must not traverse descendants, rewrite credits, or reclaim spent-input edges. Those operations belong to the event handlers that own graph mutation.

### 4.3 `DeleteTx`

`DeleteTx` remains the ordinary user-facing cleanup path for one unmined leaf transaction.

It is intentionally narrower than invalidation. Invalid or historical rows such as `failed`, `replaced`, and `orphaned` must not be erased through this path.

### 4.4 `InvalidateUnminedTx`

`InvalidateUnminedTx` is the public system-driven invalidation path for one wallet-owned unmined branch.

The canonical example is publisher-side cleanup after a local unmined transaction is known to be invalid. The method invalidates the root transaction and any dependent descendants inside one atomic transaction.

### 4.5 `RollbackToBlock`

`RollbackToBlock` owns the reorg event.

It may internally:

- detach blocks
- rewind wallet sync-state references
- orphan disconnected coinbase roots
- invalidate descendant unmined branches that depended on those roots

Rollback therefore remains the public place where coinbase invalidation begins.

## 5. kvdb and SQL Semantics

The current `kvdb` backend and the SQL backends are not identical internally.

- `kvdb` removes invalid unmined branches through the legacy `wtxmgr` conflict-removal logic
- SQL retains richer explicit transaction states such as `failed`, `replaced`, and `orphaned`

The public API is designed so both backends can still express the same wallet events. The SQL backends may preserve more detailed invalid-history state internally, while `kvdb` can continue wrapping the legacy event handlers until its semantics are lifted later.

## 6. Ops Pattern

Several mutation methods use the `ops` pattern documented in `wallet/internal/db/README.md`.

When postgres and sqlite share the same high-level workflow but differ in query bindings or row types, the shared sequencing lives in one backend-independent helper and each backend supplies a small adapter that performs the concrete query work.

This keeps one copy of the domain workflow while still making backend-specific SQL details explicit.
