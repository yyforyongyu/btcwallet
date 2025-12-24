# Wallet Rescan and State Management Design

## 1. Objectives

1.  **Manual Rescan:** Allow power users to rewind the wallet to a specific block and rescan for missing transactions.
2.  **Targeted Import Rescan:** When importing keys or accounts, automatically scan for their history without rewinding the entire wallet state (preserving the sync status of existing keys).
3.  **Safe Concurrency:** Prevent dangerous operations (like spending coins) while the wallet state is inconsistent or actively changing during a rescan.

## 2. State Management

We will refine the wallet's state model to clearly distinguish between lifecycle states and synchronization states.

### 2.1 Wallet Lifecycle State
Used to control startup/shutdown and API availability.

```go
type WalletStatus uint8

const (
    StatusStopped WalletStatus = iota
    StatusStarting
    StatusRunning
    StatusStopping
)
```

### 2.2 Synchronization State
Used to inform the UI and internal logic about what the chain backend interaction is currently doing.

```go
type SyncState uint8

const (
    // Synced: The wallet is caught up to the chain tip.
    Synced SyncState = iota

    // Syncing: The wallet is performing a standard catch-up to the chain tip 
    // (e.g., after being offline).
    Syncing

    // Rescanning: The wallet is performing a historical scan for specific data 
    // (Targeted) or has rewound its state (Manual).
    Rescanning
)
```

## 3. Workflow: Targeted Rescan (Imports)

Unlike a full rescan, a targeted rescan does **not** rewind the global `SyncedTo` height. It keeps the wallet "synced" for all existing keys while running a background job to check history for the *new* keys.

1.  **User Action:** Calls `ImportAccount(..., dryRun=false)`.
2.  **Immediate Result:** The account is saved to DB.
3.  **Job Dispatch:** `ImportAccount` sends a `RescanJob` to the `chainLoop`:
    ```go
    type RescanJob struct {
        StartHeight int32
        // If Targets is non-nil, this is a Targeted Rescan.
        // If nil, it is a Full Rescan (Rewind).
        Targets []waddrmgr.KeyScope 
        // Or specific addresses...
    }
    ```
4.  **Chain Loop Processing:**
    *   Detects `Targets`.
    *   **Does NOT** call `rollbackWallet`.
    *   Sets `SyncState = Rescanning`.
    *   Constructs a **Partial RecoveryState** containing *only* the new targets.
    *   Calls `scanBlocks(partialRecoveryState, job.StartHeight, currentTip)`.
    *   Inserts found transactions.
    *   Sets `SyncState = Synced`.

## 4. Workflow: Manual Rescan (Rewind)

1.  **User Action:** Calls `Rescan(ctx, startHeight)`.
2.  **Job Dispatch:** Sends `RescanJob{StartHeight: H, Targets: nil}`.
3.  **Chain Loop Processing:**
    *   Detects `Targets == nil`.
    *   Calls `rollbackWallet(H)`.
    *   Sets `SyncState = Syncing` (since we are effectively behind now).
    *   The standard sync loop naturally picks up from `H` and scans forward for *all* keys.

## 5. Method Availability (Access Control)

To ensure safety, certain operations must be restricted based on the `SyncState`.

| Component | Method | Synced | Syncing (Catch-up) | Rescanning (Targeted) | Reason |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AccountMgr** | `Balance` | ✅ | ✅ (Partial) | ✅ (Partial) | Safe read. |
| **AddressMgr** | `NewAddress` | ✅ | ✅ | ✅ | Independent of chain state. |
| **TxCreator** | `CreateTransaction` | ✅ | ❌ Error | ❌ Error | **Unsafe.** UTXO set is unstable. |
| **Signer** | `SignPsbt` | ✅ | ✅ | ✅ | Signing is stateless/crypto-only. |
| **TxPublisher** | `Broadcast` | ✅ | ✅ | ✅ | Best-effort is acceptable. |
| **UtxoMgr** | `ListUnspent` | ✅ | ✅ (Stale) | ✅ (Stale) | Safe read. |

**Policy:** We will enforce an error (`ErrWalletRescanning`) in `CreateTransaction` and `FundPsbt` if `SyncState != Synced`.

## 6. Implementation Plan

1.  **Refactor `scanBlocks`:** Decouple it from `prepareRecoveryState`. It should accept a `RecoveryState` interface or struct passed by the caller. This allows passing either a "Full" state (for syncing) or a "Partial" state (for targeted rescan).
2.  **Define `RescanJob`:** Update the existing job structure in `wallet.go`.
3.  **Update `Import*` methods:** Trigger the job instead of doing nothing or blocking.
4.  **Implement `Rescan`:** Add the public method to `Controller`.
5.  **Add `SyncState` Check:** Add a helper `requireSynced()` to `CreateTransaction`.
