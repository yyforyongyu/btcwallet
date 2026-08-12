# ADR 0005: Explicit Rescan on Import

## 1. Context

Importing a key, address, script, or account adds wallet state that needs two
different kinds of chain synchronization:

- Live discovery watches for transactions from the current chain tip onward.
- Historical recovery searches blocks that precede the live watch.

Starting historical recovery automatically on every import produces redundant
scans, makes a database mutation depend on slow chain I/O, and lets an import
silently choose or alter recovery parameters. ADR 0004 therefore makes all
historical recovery explicit and keeps live-tip watch maintenance separate.

The import contract still needs precise terms for the interval between the
database commit and asynchronous live-watch delivery. Those terms apply to
watch-chain scripts created by maintained allocation and import paths; they do
not describe historical completeness.

## 2. Decision

Import methods are synchronous database operations. They persist the imported
wallet state, commit, and return without waiting for chain I/O. An import that
creates a watchable script commits that script and its durable live-watch
obligation together. An account-only import creates no receiving script and
therefore no live-watch obligation; a later address allocation owns its first
watchable script and obligation. No import starts historical recovery.

### 2.1 Live-Watch Terminology

- **Accepted:** The script mutation and its durable live-watch obligation have
  committed. The script is durable wallet state, but live delivery need not be
  complete yet.
- **Pending:** The script is accepted and its live watch is awaiting or
  retrying asynchronous delivery to the chain backend.
- **Ready:** The accepted live watch has been delivered at the live-tip
  boundary. The script is eligible for live discovery from that boundary
  forward.

`Accepted`, `pending`, and `ready` describe only live discovery. None of them
means that blocks before the live-tip boundary have been scanned. A caller must
use the explicit historical recovery contract in ADR 0004 to establish
historical completeness. An account-only import is accepted when its database
state commits, but it has no pending or ready script until a later allocation
creates one.

### 2.2 Operation Timeline

For a mutation that creates a watch-chain script, the authoritative sequence
is:

1. The database transaction commits the script mutation and durable live-watch
   obligation together.
2. The mutation is accepted and the importing method returns synchronously.
   It does not wait for the chain backend or initiate a historical scan.
3. Live-tip delivery runs asynchronously. The script remains pending until
   delivery succeeds and then becomes ready.
4. If history is required, the caller separately requests either targeted
   semantic-account recovery or full-wallet recovery.

A restart or transient chain failure does not turn an accepted script into an
unaccepted one. An incomplete live delivery remains pending and is eligible for
retry. This decision requires durable obligation semantics, but it does not
choose an outbox schema, replay mechanism, backend operation, waiter design, or
durable rescan-job architecture.

### 2.3 Historical Recovery Routes

Account-scoped history uses the separately accepted semantic recovery-target
contract. Accountless raw imports cannot be named by that contract and require
an explicit full-wallet historical scan. Neither route is selected or started
by the import itself.

## 3. Examples

- **Allocation:** Committing an allocated watch-chain script accepts its live
  obligation. The script may be pending before it becomes ready; no historical
  recovery starts.
- **Account-only import:** Committing an account accepts its database state but
  creates no live obligation. A later address allocation owns the first
  watchable script and follows the accepted, pending, and ready timeline.
- **Raw import:** The import returns after database acceptance. Live delivery
  proceeds asynchronously, while discovery of older transactions requires a
  separate full-wallet recovery request.
- **Restart:** An accepted but undelivered obligation remains pending across a
  restart and can be retried without repeating historical recovery.
- **Live-tip update:** Becoming ready adds only live discovery. It does not
  establish a birthday, scan earlier blocks, or change `SyncedTo`.
- **Active historical scan:** A newly accepted live watch neither changes the
  scan's start height, target set, birthday, progress, nor completion. Delivery
  is isolated or deferred to the live-tip boundary.
- **Explicit recovery:** A semantic-account request recovers only its admitted
  account targets. A full-wallet request is the route for accountless raw
  imports and may rewind the wallet as defined by ADR 0004.

## 4. Rationale

### 4.1 Batch Efficiency

Callers can batch imports and then request one historical recovery operation
with deliberate parameters instead of starting one scan per mutation.

### 4.2 API Clarity

Database acceptance, asynchronous live readiness, and historical recovery have
separate completion conditions. Import latency is bounded by database work,
while callers that need live readiness or historical completeness can wait for
the corresponding operation explicitly.

### 4.3 Recovery Isolation

Live-watch maintenance cannot widen or restart an active historical scan.
Recovery range, target, and birthday decisions remain owned by the explicit
request described in ADR 0004.

## 5. Consequences

### Pros

- Import methods remain fast, atomic database operations.
- Accepted live-watch obligations survive delays, failures, and restarts.
- Callers can distinguish durable acceptance from live readiness and
  historical completeness.
- Bulk imports do not create automatic historical scan storms.

### Cons

- Clients that need immediate live readiness must handle a pending result.
- Clients must explicitly request historical recovery when they need old
  transactions.
- A ready script can correctly show no historical funds until recovery runs.

## 6. Status

Accepted.

## 7. References

- [ADR 0004](0004-targeted-rescan-vs-rewind.md): historical recovery modes and
  isolation from live-tip watch maintenance.
