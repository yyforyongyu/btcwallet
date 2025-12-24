# Rescan and Recovery Improvements

This document tracks architectural issues and optimization opportunities identified within the legacy wallet synchronization and recovery logic.

## Identified Legacy Issues

1.  **Memory Leak in `DeriveFromKeyPath`**:
    - The `waddrmgr` method `DeriveFromKeyPath` calls `keyToManaged`, which unconditionally appends the derived address to the internal `deriveOnUnlock` list (if the key is public).
    - This list is intended to defer private key derivation until the wallet is unlocked.
    - During large rescans or recovery operations (e.g., deriving 2500 lookahead addresses), this list grows unbounded with every derived candidate, even if the address is never used or persisted to the database. This creates significant memory pressure during long-running syncs.

2.  **Inefficient DB Access in Derivation**:
    - `DeriveFromKeyPath` requires a `walletdb.ReadBucket` argument, mandating an open database transaction for every address derivation.
    - This strict coupling prevents efficient in-memory lookahead generation (e.g., generating thousands of candidates to match against a filter) without managing database transaction lifecycles and potential lock contention.

3.  **Blocking Startup Synchronization**:
    - The legacy `syncWithChain` process runs synchronously at startup, blocking the wallet from becoming ready until it catches up to the chain tip.
    - This prevents the wallet from serving other requests (like `Info` or `Unlock`) during the initial sync phase.

4.  **RPC Calls Inside Database Transactions**:
    - The legacy rollback check logic (`syncWithChain`) performs network RPC calls (e.g., `GetBlockHash`) while holding a write lock on the wallet database.
    - If the network request is slow or hangs, the database lock is held indefinitely, blocking all other wallet operations (e.g., creating addresses, querying balances) and causing potential application freezes.

5.  **Inefficient Bandwidth Usage**:
    - The legacy `FilterBlocks` approach sends the entire set of watched addresses to the chain backend for every batch.
    - This consumes significant bandwidth and processing power on the backend, especially for wallets with large address lookahead windows.

6.  **Single Account Limitation in Recovery**:
    - The legacy `expandScopeHorizons` function (and by extension the recovery logic) hardcodes `waddrmgr.DefaultAccountNum` (0) when expanding address lookahead windows.
    - This means that for wallets with multiple accounts (e.g., imported accounts or additional BIP44 accounts), the recovery process will fail to discover and track addresses for any account other than the default one.

7.  **Single Account Limitation in Resurrect**:
    - The `RecoveryManager.Resurrect` method, used to initialize the recovery state from the database, only loads account properties for the default account (0).
    - This means that any existing addresses or state for non-default accounts are ignored during the initialization of a recovery scan, potentially causing the wallet to miss funds belonging to those accounts if they are not re-discovered by the gap limit mechanism (which might also fail if started from 0).

8.  **Memory Leak in `RecoveryState` (Addresses & Outpoints)**:
    - The `RecoveryState`'s internal maps (`BranchRecoveryState.addresses` for derived keys and `RecoveryState.watchedOutPoints` for UTXOs) are populated during `Resurrect` and subsequent operations.
    - However, there is no explicit garbage collection or pruning logic to remove addresses or outpoints that fall outside the active lookahead window or are spent.
    - This can lead to these maps growing indefinitely over the wallet's lifecycle, consuming increasing amounts of memory, especially for wallets with extensive transaction history or long-running operations.

9.  **Redundant Database Indexing**:
    - The `waddrmgr` database schema appears to maintain redundant indexing for addresses.
    - `addrBucket` stores address data keyed by script hash (including the account ID).
    - `addrAcctIdxBucket` stores a mapping of `script hash -> account ID`.
    - `addrAcctIdxBucket` *also* contains nested buckets per account ID, mapping `script hash -> null`.
    - This structure duplicates the account association multiple times, increasing storage size and write amplification during address creation.
10. **Single Scope Limitation in Credit Processing**:
    - The `addRelevantTx` method in `wallet/chainntfns.go` (and by extension the new ingestion logic) includes an explicit check that skips processing for any address that does not belong to the "default scope" (BIP44/BIP84/BIP49).
    - Specifically, the check `!waddrmgr.IsDefaultScope(scopedManager.Scope())` prevents outputs from being marked as credits if they belong to non-standard or custom key scopes.
    - This effectively means the wallet will fail to credit funds to imported addresses or other non-default accounts, treating them as unspendable even if the transaction is recorded.

