# Wallet State Management

This document describes the architectural design of the wallet's state management system.

## Core Philosophy

The wallet state is managed using an **Orthogonal State Model**. Instead of a single monolithic state enum (e.g., "Syncing", "Locked", "Stopped"), we track three independent dimensions of state. This decoupling allows for precise representation of complex conditions (e.g., "Started" AND "BackendSyncing" AND "Locked") without combinatorial explosion.

The state logic is strictly encapsulated within the `walletState` struct in `wallet/state.go`, ensuring that all transitions are atomic and validated.

## The Three Dimensions

### 1. Lifecycle (System State)
Tracks the runtime status of the wallet's main event loop and background processes.

*   **Type:** `lifecycle` (enum)
*   **States:**
    *   `Stopped`: The wallet is idle. No background routines are running.
    *   `Started`: The wallet is fully operational. `mainLoop` and `chainLoop` are running.
    *   `Stopping`: A shutdown signal has been sent, and the wallet is waiting for routines to exit.
*   **Transitions:**
    *   `Stopped` -> `Started`: Triggered by `Start()`. Atomic CAS ensures single initialization.
    *   `Started` -> `Stopping`: Triggered by `Stop()`.
    *   `Stopping` -> `Stopped`: Finalization of `Stop()`.

### 2. Synchronization (Chain State)
Tracks the data freshness relative to the blockchain backend.

*   **Type:** `syncState` (enum)
*   **States:**
    *   `BackendSyncing`: Waiting for the connected chain backend (e.g., bitcoind, neutrino) to finish its own sync.
    *   `Syncing`: The wallet is actively downloading blocks or filters to catch up to the chain tip.
    *   `Synced`: The wallet is fully caught up with the chain tip.
    *   `Rescanning`: The wallet is performing a targeted historical scan for specific accounts/addresses (does not affect global tip).
*   **Reset:** Resets to `BackendSyncing` whenever the wallet is `Start`ed.

### 3. Authentication (Security State)
Tracks the accessibility of sensitive key material.

*   **Type:** `bool` (flag)
*   **Fields:** `unlocked` (atomic boolean).
*   **States:**
    *   **Locked** (`unlocked=false`): Private keys are encrypted/inaccessible.
    *   **Unlocked** (`unlocked=true`): Private keys are available in memory.
*   **Security Design:** We track the `unlocked` state rather than `locked` so that the zero-value (`false`) defaults to the secure state (**Locked**). The wallet is forcefully locked upon `Stop()`.

## State Transitions & Safety

Direct access to state fields is forbidden. All mutations occur via semantic methods that enforce invariants.

### Startup Flow (`Start`)
1.  **Atomic Transition:** `transitionToStarted()` moves lifecycle from `Stopped` -> `Started`. Fails if already running.
2.  **State Reset:**
    *   Sync state -> `BackendSyncing`
    *   Auth state -> **Locked** (Secure default)
3.  **Resource Init:** The `quit` channel is initialized *only* after the state transition succeeds.
4.  **Runtime Setup:** Birthday verification and account loading occur. If these fail, the state is reverted to `Stopped`.

### Shutdown Flow (`Stop`)
1.  **Transition:** `transitionToStopping()` marks the wallet as shutting down.
2.  **Resource Cleanup:** The `quit` channel is closed to signal background routines.
3.  **Wait:** Blocks until `wg` counter reaches zero.
4.  **Finalize:** `transitionToStopped()` marks lifecycle as `Stopped` and forcefully **Locks** the wallet.

## Error Handling

State-related errors are unified under `ErrStateForbidden`. Specific conditions are wrapped to provide context:
*   `fmt.Errorf("%w: wallet not started", ErrStateForbidden)`
*   `fmt.Errorf("%w: wallet locked", ErrStateForbidden)`
*   `fmt.Errorf("%w: wallet is currently %s", ErrStateForbidden, syncState)`

Callers can check `errors.Is(err, ErrStateForbidden)` to handle rejections gracefully.
