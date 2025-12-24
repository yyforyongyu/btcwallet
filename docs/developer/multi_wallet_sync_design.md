# Multi-Wallet Synchronization Design

This document outlines the architectural design for supporting multiple wallets within a single `btcwallet` process (e.g., for SQLization support), focusing on efficient chain synchronization and state management.

## 1. Core Philosophy: Manager-Centric Synchronization

To support multiple wallets without multiplying network overhead, the `Manager` becomes the central orchestrator of all blockchain interactions. Individual `Wallet` instances become passive consumers of chain data.

### Key Principles
*   **One Chain Connection:** The `Manager` holds the sole `chain.Interface` connection.
*   **One Chain Loop:** A single goroutine in the `Manager` drives synchronization for *all* active wallets.
*   **Lockstep Sync:** All active wallets move through chain history together. Divergent states (e.g., a new wallet import) are handled by a dedicated catch-up phase that temporarily pauses the global loop.
*   **Atomic Updates:** Block ingestion for multiple wallets happens within a single database transaction (where feasible) to ensure consistency.

## 2. The "Stop-the-World" Import Strategy

Handling wallets at different heights (e.g., Wallet A at tip, Wallet B importing from height 0) is the primary challenge. We adopt a **Blocking Import** strategy to maintain architectural simplicity.

### Workflow: Importing a Wallet
1.  **Pause:** The Manager pauses the global `chainLoop`. No new blocks are processed for existing synced wallets.
2.  **Mount:** The new wallet is initialized. Its state is "Not Synced" (Height X).
3.  **Catch-Up:** The Manager runs a dedicated, temporary scan loop from `Height X` to `Current Tip`.
    *   **Scope:** This scan matches *only* the new wallet's addresses/scripts.
    *   **Efficiency:** It ignores existing wallets (they are already synced).
4.  **Resume:** Once the new wallet catches up to the global tip, it joins the active set. The global `chainLoop` resumes, feeding new blocks to all wallets simultaneously.

### Workflow: Targeted Address Import
When importing an address into a specific wallet, the process is identical but faster:
1.  **Pause:** Global loop pauses.
2.  **Scan:** Manager runs `rescanTargeted` for the specific address/outpoint range.
3.  **Resume:** Global loop resumes.

**Trade-offs:**
*   **Pros:** Eliminates the complexity of concurrent scan loops at different heights. Prevents race conditions. Maximizes I/O efficiency.
*   **Cons:** Existing wallets stop receiving updates during the import. For address imports, this is negligible (seconds). For full wallet restores, this is acceptable "maintenance mode" behavior.

## 3. Architecture Changes

### 3.1 The Manager
The `Manager` absorbs the responsibilities previously held by `wallet/sync.go`.

*   **`SyncCoordinator`**: A new component within the Manager (or part of the Manager struct) that owns:
    *   `chainLoop`
    *   `RecoveryState` (Global, or aggregate of wallet states)
    *   `chainClient`
*   **Methods:**
    *   `Start()` / `Stop()`: Controls the global sync loop.
    *   `Register(w *Wallet)`: Adds a wallet to the active sync set.
    *   `ImportWallet(w *Wallet)`: Orchestrates the Stop-CatchUp-Resume flow.

### 3.2 The Wallet
The `Wallet` struct becomes lighter.

*   **Removed:** `chainLoop`, `chainClient`, `scanBatch`, `rescan...` methods.
*   **Added:**
    *   `GetLookahead()`: Returns data needed for CFilter matching.
    *   `Ingest(dbtx, block)`: Processes a block, identifying relevant txs and updating the DB.
    *   `SetSyncedTo(dbtx, header)`: Updates local sync state.

### 3.3 Data Flow (New Block)

1.  **Fetch:** Manager fetches CFilters for Block N.
2.  **Match:** Manager checks filters against the aggregate watchlist of *all* active wallets.
3.  **Download:** If *any* wallet matches Block N, Manager downloads the block *once*.
4.  **Process:** Manager opens a DB Transaction.
    *   Calls `WalletA.Ingest(dbtx, block)`.
    *   Calls `WalletB.Ingest(dbtx, block)`.
    *   Updates `SyncedTo` for all wallets.
    *   Commits DB Transaction.

## 4. State Management Refactor

With the Manager controlling sync, the `walletState` (Orthogonal Model) needs adjustment.

*   **Wallet State**: Tracks lifecycle (`Started/Stopped`) and Auth (`Locked/Unlocked`). The `Sync` dimension becomes a read-only status reflecting the Manager's view.
*   **Manager State**: Tracks the chain connection status (`Connected`, `Syncing`, `Offline`).

## 5. Migration Path

The refactoring performed in `wallet/controller.go` vs `wallet/sync.go` (splitting Lifecycle from Sync logic) is the prerequisite for this design. The next steps for SQLization/Multi-Wallet would be:

1.  **Lift `sync.go`**: Move the logic from `wallet/sync.go` into a `Manager`-level component.
2.  **Abstract Storage**: Update the sync logic to accept a list of `Wallet` interfaces (or structs) instead of operating on `w.txStore`/`w.addrStore` directly.
3.  **Implement Blocking Import**: Add the pause/resume capability to the Manager's loop.
