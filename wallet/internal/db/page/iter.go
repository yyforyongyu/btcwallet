package page

import (
	"context"
	"errors"
	"fmt"
	"iter"
)

// errPageNoCursor is a sentinel for an internal invariant violation: a
// fetchPage implementation returned HasMore=true with a nil LastCursor. This
// should never happen in correct code; it indicates a bug in the fetchPage
// implementation.
var errPageNoCursor = errors.New("page has more results but no cursor")

// Iter iterates through paginated results by repeatedly fetching pages and
// yielding items. It stops when fetchPage returns HasMore=false, so
// early-exhaustion mode avoids an extra empty-page round-trip.
//
// The query parameter is caller-defined (e.g., ListAccountsQuery) and is
// updated via setCursor between page fetches. The setCursor function receives
// the current query and the LastCursor from the just-fetched page, and must
// return the updated query for the next fetch.
//
// The entity parameter is a human-readable resource name (e.g., "account",
// "transaction"), used only in error messages.
//
// The fetchPage function must honour ctx and return an error if cancelled.
//
// Iter stops when HasMore is false, when yield returns false (caller break),
// or when fetchPage returns an error. Errors are yielded as the second value;
// the iterator terminates after the first error. Cancellation is only observed
// between page fetches, and only if fetchPage checks ctx.
func Iter[Query, Item, Cursor any](ctx context.Context, query Query,
	entity string,
	fetchPage func(context.Context, Query) (Result[Item, Cursor], error),
	setCursor func(Query, Cursor) Query) iter.Seq2[Item, error] {

	return func(yield func(Item, error) bool) {
		var zero Item

		for {
			result, err := fetchPage(ctx, query)
			if err != nil {
				// iter.Seq2 requires errors to be yielded as (zero, err) pairs
				// rather than returned directly. The iterator terminates after
				// this yield, so the error propagates to the caller as the
				// second value in the range loop.
				yield(zero, err)

				return
			}

			for _, item := range result.Items {
				if !yield(item, nil) {
					return
				}
			}

			if !result.HasMore {
				return
			}

			// HasMore=true with LastCursor=nil violates the Result invariant
			// and indicates a bug in the fetchPage implementation. This is
			// treated as a fatal invariant violation rather than a silent
			// error, ensuring the caller is alerted to the programming mistake
			// in the fetch implementation.
			if result.LastCursor == nil {
				yield(zero, fmt.Errorf("page for %s: %w", entity,
					errPageNoCursor),
				)

				return
			}

			// Advance the query cursor only after the current page is fully
			// yielded to the caller, and we've verified a valid cursor exists
			// for the next fetch. This ensures the query advances one page at
			// a time in lockstep with item consumption.
			query = setCursor(query, *result.LastCursor)
		}
	}
}
