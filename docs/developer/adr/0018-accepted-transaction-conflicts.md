# ADR 0018: Accepted Transaction Conflicts

## Status

- **Status:** Accepted
- **Date:** 2026-11-02

## Relationships

- **Amends:** [ADR 0006](0006-wtxmgr-sql-schema.md) for accepted unmined
  replacements and confirmation of invalidated regular transactions.
- **Supersedes:** None.
- **Amended by:** None.
- **Superseded by:** None.

## 1. Problem

SQL rejects a competing unmined spend before the publisher can send it. The
existing branch must survive refusal, while an accepted replacement must
become active. A miner may still confirm the original branch, so an unmined
conflict cannot permanently exclude its actual confirming transactions.

## 2. Context

Wallet records ordinary publication attempts before sending and retains them
on send failure. SQL already reconciles confirmed conflicts atomically, with
existing graph ordering, descendant invalidation, and spend-edge updates.
Native KVDB instead keeps competing unmined claims until confirmation.

### Constraints

- Rejected publication preserves the existing graph and causal send error.
- Accepted SQL replacement and confirming history use existing atomic writes.
- Retain history, labels, wallet isolation, and backend-specific claim policy.
- Add no schema, lock, worker, coordinator, or RPC change.

## 3. Decision

`CreateTxParams.ReplaceUnmined` permits recording a competing unmined send
after acceptance. SQL reconciles its active branch using the existing
confirmed-conflict workflow. Ordinary prepublication writes leave the flag
false; a conflicting attempt is sent before its accepted graph is recorded.

A real confirming observation may restore the same regular transaction row
from `replaced` or `failed` to `published`, with block identity, credits, and
input claims reconciled atomically. A descendant is restored only when it is
itself observed confirmed. Unmined echoes do not revive invalidated rows.

Native KVDB retains competing unmined claims until confirmation because an
SPV send may be an orphan. The shared flag does not impose SQL's active-branch
policy on that backend. Its separate admission repair remains outside PR2.

## 4. Rationale

The send result supplies the acceptance boundary, while a block supplies the
stronger authoritative fact. Reusing existing Store transactions preserves
atomicity without another state owner. This partially amends ADR 0006's
original claim that failed history is permanently invalid.

## 5. Alternatives Considered

### Alternative: Replace before sending

This releases the existing branch even when the backend refuses the new send.

### Alternative: Keep invalidated rows permanently terminal

This prevents the wallet from recording an actual block containing the old
branch. Removing and reinserting rows would also lose retained identity.

## 6. Consequences

### Positive

Refusal preserves existing claims. Acceptance updates SQL history atomically,
and actual confirmation can restore either branch without deleting its rows.

### Negative and Risks

Network publication and database persistence remain separate operations. An
accepted send may be followed by a recording error, which must stay visible to
the caller; ordinary chain observations use the same reconciliation contract.

## 7. Implementation Overview

Wallet uses the existing publisher, Store CreateTx contract, and syncer
observation batch. SQL retains its graph lock and transaction runtime. Current
lifecycle documentation distinguishes invalid unmined state from confirming
block truth. Existing KVDB claim handling remains native.

## 8. References

- [Transaction invalidation flows](../tx_invalidation_flows.md).
- [Wallet data model](../utxo_data_model.md).
- [Issue 64 extraction evidence](https://github.com/yyforyongyu/btcwallet-sql-roadmap/issues/64).
