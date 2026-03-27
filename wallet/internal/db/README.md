# wallet/internal/db

This package keeps the public wallet-store APIs in one place while supporting
multiple SQL backends.

## Ops interfaces

Some store methods use a small backend-specific `ops` interface together with a
shared backend-independent helper.

Here, `ops` is short for the backend-specific database operations that one
shared workflow needs.

We use this pattern because postgres and sqlite usually agree on the high-level
wallet workflow, but they still differ in important low-level ways:

- sqlc generates different parameter and row types for each backend
- nullable arguments often have different shapes, such as typed `sql.Null*`
  values in postgres versus sqlite-specific generated forms
- integer widths and conversion helpers differ across backend bindings
- some statements need backend-specific SQL or binding workarounds
- we still want compile-time checking against each backend's concrete query set

Without a small adapter layer, each backend file tends to duplicate the same
business workflow with only query-shape differences. That makes reviews noisy
and makes later invariant changes easy to miss in one backend.

Use this pattern when a method has both of these properties:

- the high-level workflow is the same for postgres and sqlite
- the SQL query types, nullable argument shapes, or row handling differ by
  backend

In that case:

- keep the shared workflow in one backend-independent helper
- keep the backend adapters close to the concrete backend methods
- keep shared unit tests near the shared workflow
- keep backend-visible behavior in integration tests

This approach is meant to keep one copy of the domain workflow while still
leaving backend-specific SQL details explicit and close to the actual queries.
The shared helper owns the sequencing and invariants. The backend `ops`
implementation owns query calls, generated binding types, and backend-specific
conversions.

Examples:

- tx store: `CreateTx`, `UpdateTx`, `DeleteTx`, `RollbackToBlock`
- utxo store: `LeaseOutput`, `ReleaseOutput`

Minimal example:

```go
type someMethodOps interface {
	load(ctx context.Context, id int64) (row, error)
	write(ctx context.Context, req request) error
}

func someMethodWithOps(ctx context.Context, req request,
	ops someMethodOps) error {
	loaded, err := ops.load(ctx, req.id)
	if err != nil {
		return err
	}

	return ops.write(ctx, mergeRequest(req, loaded))
}
```

The shared helper owns the ordering and invariants. Each backend `ops`
implementation only adapts query calls, generated sqlc types, and backend-
specific conversions.

Do not introduce an `ops` interface for thin read methods or simple wrappers.
If a method is mostly one query plus row conversion, prefer direct backend
implementations. Examples include `GetTx`, `ListTxns`, `GetUtxo`,
`ListUTXOs`, `ListLeasedOutputs`, and `Balance`.

## File layout

- shared helpers and shared workflows should stay backend-independent
- backend-specific implementations should stay close to the concrete backend
- method-specific files are preferred over large backend files that mix many
  unrelated methods

This layout keeps commit boundaries small, makes review easier, and lets shared
logic evolve without hiding backend-specific SQL details.
