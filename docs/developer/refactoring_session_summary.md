### Detailed Summary of Accomplishments (Since `prep-controller`)

This session has focused on a significant refactoring of the `btcwallet`'s scanning and recovery logic, primarily affecting the `wallet` package, with supporting changes in `waddrmgr` and `chain` interfaces/mocks. The overarching goal was to implement optimized batch fetching and processing, improve multi-account support, enhance memory efficiency, and improve architectural clarity.

**Core Architectural Shift & Recovery Logic (`wallet/recovery.go`):**

*   **`RecoveryState` Centralization:** `RecoveryState` was enhanced to be the central authority for managing derivation branch states, flattening previous complex structures. It now directly holds `branchStates` (map of `BranchScope` to `BranchRecoveryState`) and `addrFilters` (map of addresses to `AddrFilterEntry`).
*   **`NewRecoveryState` Enhancement:** The constructor now takes `chainParams` and `addrMgr` directly, reducing dependencies.
*   **`GetBranchState`:** Introduced as the source of truth for `BranchRecoveryState`, retrieving or creating instances. Enhanced its documentation for clarity.
*   **`AddrFilterEntry`:**
    *   Renamed from `addrFilterEntry` to `AddrFilterEntry` (public type) for consistency with its usage in exported types.
    *   Fields were initially privatized, then re-exported (`Address`, `AddrScope`, `IsLookahead`) to maintain consistency with the public type and enable direct access when wrapped in other public types.
    *   `IsLookahead` comment was clarified to specify "finding this address *in the block* triggers horizon expansion."
    *   The `HasDerivation` field was removed after analysis showed it was redundant with `IsLookahead` in the context of horizon expansion logic.
*   **`Initialize` Method:** Refactored to iterate through `AccountProperties` and call `initAccountState` for each, ensuring proper multi-account setup. Logic for populating historical addresses was updated to use `AddrFilterEntry`.
*   **`initAccountState`:** New private helper method added to orchestrate `buildAddrFilters` for external and internal branches of a given account. Detailed documentation was added.
*   **`buildAddrFilters`:** Refined to directly derive addresses and create `AddrFilterEntry` instances for lookahead addresses. Syntax/formatting issues in its loop body were meticulously fixed.
*   **`BuildCFilterData`:** Comment and variable name updated from "Estimate size" to "Calculate size" as the calculation is exact.
*   **`reportFound`:** Logic was updated to aggregate `FoundHorizons` (max index per branch) from individual `AddrScope` matches, returning this aggregated map. An error log was added for unexpected `GetBranchState` failures.
*   **`filterBlock` & `filterTx` (Extraction and Error Handling):**
    *   The core transaction filtering logic was extracted from `filterBlock` into a new private helper method `filterTx`. This significantly improved modularity.
    *   `filterTx` now properly handles errors from `txscript.ExtractPkScriptAddrs` (logging non-standard scripts at debug level).
    *   The variable `outAddrs` was renamed to `addrs` in `filterTx` for clarity.
*   **`MatchedOutputs` Type:** Introduced a new public type `MatchedOutputs` (`map[chainhash.Hash]map[uint32][]AddrFilterEntry`) to cleanly encapsulate matched output data, supporting multiple addresses matching a single transaction output.

**Scanning Flow & Efficiency (`wallet/controller.go`):**

*   **`scanResult` Struct:**
    *   Refactored to **embed `*BlockProcessResult`** and remove the redundant `block` field. This was a critical memory optimization, preventing the accumulation of large `wire.MsgBlock` objects in memory for the entire batch.
    *   All usages across `scanBatchWithCFilters`, `scanBatchWithFullBlocks`, `updateAddress`, and `updateUTXOs` were updated to correctly access fields via the embedded struct.
*   **`scanBlocks` Optimizations:**
    *   Added an `Empty()` method to `RecoveryState` and integrated it into `scanBlocks`. This allows `scanBlocks` to skip execution entirely if there are no addresses or outpoints to watch, saving CPU cycles.
    *   Updated debug logging in `scanBlocks` to use `RecoveryState.String()` for a concise overview, and changed the skipped scan log level to `Info`.
*   **`fetchAndMatchCFilters` & `reMatchAndFetch` -> `matchAndFetch` (Unification):**
    *   The initial CFilter fetching/matching logic and the subsequent re-matching logic (after horizon expansion) were unified into a single private helper method `matchAndFetch`. This significantly reduced code duplication in `scanBatchWithCFilters`.
*   **Error Handling Consistency:** `ProcessBlock` failure in `scanBatchWithCFilters` was changed to return an error instead of just logging and breaking.
*   **Unwrapped Error Checks:** Systematically unwrapped `if err := ...` error checks in `handleRescanRequest`, `checkRollback`, `updateAddress`, `updateUTXOs`, and `insertRelevantTx` for improved Go idiomacy and readability.
*   **`isChange` Variable:** Introduced `isChange` variable in `insertRelevantTx` for clarity.

**Address Manager Enhancements (`waddrmgr/scoped_manager.go`, `waddrmgr/interface.go`):**

*   **`ExtendAddresses`:** Added to `AccountStore` interface and `ScopedKeyManager` implementation.
*   **`ActiveAccounts`:** Added to `AccountStore` interface and `ScopedKeyManager` implementation.
*   **`DeriveAddr`:** Added to `AccountStore` interface and `ScopedKeyManager` implementation.
*   **`IsChange()` Methods:** Added to `BranchScope` and `AddrScope` to encapsulate the logic for identifying internal (change) branches, leading to cleaner code in `insertRelevantTx`.

**Transaction Manager Enhancements (`wtxmgr/interface.go`, `wtxmgr/tx.go`):**

*   **`InsertConfirmedTx`:** Added to `TxStore` interface and `Store` implementation. This enables atomic insertion of a mined transaction and all its identified credits, reducing DB overhead.
*   **`CreditEntry`:** New struct introduced to support `InsertConfirmedTx`.

**Legacy Code Management:**

*   `RecoveryManager` struct and its methods are explicitly marked `TODO(yy): Deprecated, remove.` across `wallet/recovery.go`. `ScopeRecoveryState` and `watchedOutPoints` fields in `RecoveryState` are similarly marked.
*   `expandScopeHorizons` in `wallet/wallet.go` is marked deprecated with a note about inefficiency.
*   Deprecated `StartDeprecated`, `StopDeprecated`, `UnlockDeprecated`, `LockDeprecated`, `CreateDeprecated` methods were added to `wallet/deprecated.go` and their interfaces (`wallet/interface.go`).
*   `wallet/example_test.go` was updated to use these deprecated `StartDeprecated` and `StopDeprecated` methods.
