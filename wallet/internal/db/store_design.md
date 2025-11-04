### Title: `db`: Introduce Granular Database Interface

### Summary

This is a **draft PR** to introduce a new, granular database interface located in the `wallet/internal/db` package. The primary goal of this change is to create a clean abstraction layer that decouples the wallet's business logic from the underlying storage implementation (currently `waddrmgr` and `wtxmgr`).

This PR introduces the interface design only. The `KvdbStore` [implementation](https://github.com/yyforyongyu/btcwallet/blob/store-draft/wallet/internal/db/driver.go#L134) is a temporary and incomplete adapter meant to satisfy the interface, but the focus of this review should be on the design of the interfaces themselves.

### Motivation

Currently, the wallet's core logic is tightly coupled to the legacy `waddrmgr` and `wtxmgr` managers. This has several significant drawbacks:
*   **Poor Testability:** It is very difficult to write unit tests for business logic that relies on these complex, stateful managers.
*   **Difficult Maintenance:** The lack of a clear boundary makes the code harder to reason about and refactor safely.
*   **Inflexibility:** It makes it nearly impossible to swap out the database backend. A major long-term goal is to introduce a more robust, multi-wallet SQL backend, which is blocked by the current architecture.

This new `db` interface serves as the foundation for all future database work, providing a clean contract for the rest of the application to build upon.

### The New Interface Design

The new design is split into five granular, role-based interfaces: `WalletStore`, `AccountStore`, `AddressStore`, `TxStore`, and `UTXOStore`. This separation makes the API easier to understand and implement.

The design adheres to several key principles:
*   **Consistent Use of Parameter Structs:** All methods accept a single `params` or `query` struct, which improves readability and makes the API easy to extend without breaking changes.
*   **Idiomatic Handling of Optionals:** Pointers are used for optional fields in update operations (e.g., `UpdateTxParams.Label *string`) to unambiguously signal the caller's intent for partial updates.
*   **Safe and Performant Return Types:** Methods that return a single entity return a pointer (`*AccountInfo`), providing a clear `nil` signal for "not found". Methods that return a list return a slice of values (`[]AccountInfo`), which is more performant (due to cache locality) and safer.
*   **Forward-Looking for Multi-Wallet Support:** All relevant methods accept a `WalletID`, making the interface ready for a true multi-wallet SQL implementation.

### Pros and Cons

**Pros:**
*   **Decoupling:** Provides a clean separation between business logic and data storage.
*   **Testability:** The new interfaces can be easily mocked for robust unit testing.
*   **Extensibility:** Unlocks the ability to implement new database backends (e.g., SQLite/PostgreSQL) without changing the wallet's core logic.
*   **API Safety & Ergonomics:** The consistent patterns make the API safer, more predictable, and easier to use correctly.

**Cons & Trade-offs:**
*   **Potential for "Chatty" API Calls:** The granular nature of the interfaces may require some higher-level operations to make multiple calls to the database. This is a deliberate trade-off for clarity and flexibility.
*   **Derived Data Complexity:** `TxInfo` is now a minimal record. The caller is responsible for deriving related data like credits and debits by querying the UTXO store. This is a positive trade-off for a more normalized and robust database schema.

### Draft Status & Future Work

This interface is the result of careful consideration, but it is still a draft. It is expected that as we begin to integrate it into the wallet's business logic, we may discover areas for improvement or adjustment. Feedback on the overall design and patterns is highly encouraged at this stage.

### TODOs and Next Steps

1.  Gather feedback on this initial interface design.
2.  Complete the `KvdbStore` implementation to fully satisfy the new interfaces, serving as a temporary bridge.
3.  Begin integrating the new `db` interface into the higher-level wallet logic, replacing direct calls to `waddrmgr` and `wtxmgr`.
4.  Based on real-world usage patterns observed during integration, identify any performance hotspots that may require new, specialized batch methods in the interface.
