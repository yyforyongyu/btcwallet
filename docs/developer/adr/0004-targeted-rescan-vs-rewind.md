# ADR 0004: Targeted Rescan vs. Global Rewind

## 1. Context

Discovering transactions that were missed in historical blocks requires a
recovery scan. The legacy wallet treated every recovery as a global rewind:

1. Move the wallet's global `SyncedTo` height back to the start block.
2. Put the wallet in the `Syncing` state.
3. Reprocess every block from that height for every wallet target.

A global rewind is unnecessarily disruptive when the caller needs to recover
history for a particular account. It also conflates two unrelated concerns:
recovering historical transactions and adding a script to the live chain watch.
Script-producing imports and allocations need live discovery after their
database changes commit, but they must not implicitly choose a historical start
height or alter an already-running recovery.

ADR 0005 owns the synchronous database-acceptance and asynchronous live-watch
timeline. This record owns the historical recovery modes and the boundary that
keeps live-watch maintenance from changing them.

## 2. Decision

Historical recovery and live-tip watch maintenance are separate operations
with disjoint triggers and state effects.

### 2.1 Full-Wallet Historical Recovery

- **Trigger:** An explicit full-wallet recovery request, such as `Resync(...)`.
- **Behavior:**
  - Rewinds the global `SyncedTo` watermark to the requested start point.
  - Puts the wallet in the `Syncing` state.
  - Scans for the complete wallet target set selected at admission.
- **Use case:** Repairing incomplete wallet history, recovering accountless raw
  imports, or deliberately rebuilding the wallet's historical view.

Accountless raw imports have no semantic account identity. Their historical
transactions can therefore be recovered only by an explicit full-wallet scan.
Importing the raw script does not start that scan.

### 2.2 Targeted Historical Recovery

- **Trigger:** An explicit recovery request containing semantic-account
  targets.
- **Behavior:**
  - Does not rewind the global `SyncedTo` watermark.
  - Puts the wallet in the `Rescanning` sub-state.
  - Uses only the account-scoped target set resolved under the separately
    accepted semantic recovery-target contract.
  - Scans the admitted block range and inserts matching transactions.
- **Use case:** Recovering history for one or more accounts without rewinding
  the rest of the wallet.

Raw imported scripts are excluded because they are accountless. Imports and
allocations are also not targeted-recovery triggers; the caller must make a
separate explicit request when historical discovery is required.

### 2.3 Live-Tip Watch Maintenance

Live-tip watch maintenance is not historical recovery. Once a script and its
durable live-watch obligation are accepted as defined by ADR 0005, delivery to
the chain backend proceeds asynchronously at the live-tip boundary. It scans no
historical block and does not move `SyncedTo` or enter `Syncing` or
`Rescanning`.

If historical recovery is active, live registration must remain isolated from
that recovery. It never changes the recovery's start height, target set,
birthday, progress, or completion. The watch may become effective at the
documented live-tip boundary without widening or restarting the historical
scan.

## 3. Concurrency and Safety

The historical scan state, not live-watch delivery state, controls wallet
operation restrictions:

- `CreateTransaction` and `FundPsbt` are blocked while the wallet is `Syncing`
  or `Rescanning`, because historical transaction state is being updated.
- `Balance` and `ListUnspent` remain available during targeted recovery and
  describe the history discovered so far.
- An accepted or pending live watch does not itself put the wallet in a
  historical scan state.

The target set and range of a historical request are fixed independently of
later allocations, imports, retries, restarts, and live-tip updates. Historical
completeness is established only by completion of the corresponding explicit
recovery request, never by live-watch readiness.

## 4. Consequences

### Pros

- Import and allocation do not accidentally rewind or widen wallet history.
- Account-scoped recovery avoids scanning unrelated wallet targets.
- Live discovery can progress without changing an active historical scan.
- Accountless imports have one explicit, backend-neutral historical route.

### Cons

- Callers must request historical recovery separately from script creation or
  import.
- The synchronization layer must preserve an isolation boundary between live
  watch delivery and historical scanning.
- A live-ready script may still have undiscovered historical transactions.

## 5. Status

Accepted.

## 6. References

- [ADR 0005](0005-no-auto-rescan-on-import.md): database acceptance,
  live-watch readiness, and the shared operation timeline.
