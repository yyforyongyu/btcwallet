package page

import (
	"context"
	"iter"
)

// Iter iterates through paginated results by repeatedly fetching pages and
// yielding items until exhaustion, caller break, error, or cancellation.
//
// Errors are yielded as the second value in the iterator pair. Callers must
// check the error on every iteration before using the yielded item.
func Iter[Q, T, C any](ctx context.Context, query Q,
	fetch func(context.Context, Q) (Result[T, C], error),
	withAfter func(Q, C) Q) iter.Seq2[T, error] {

	return func(yield func(T, error) bool) {
		var zero T

		for {
			if err := ctx.Err(); err != nil {
				yield(zero, err)

				return
			}

			result, err := fetch(ctx, query)
			if err != nil {
				yield(zero, err)

				return
			}

			for _, item := range result.Items {
				if err := ctx.Err(); err != nil {
					yield(zero, err)

					return
				}

				if !yield(item, nil) {
					return
				}
			}

			if !result.HasNext {
				return
			}

			query = withAfter(query, result.Next)
		}
	}
}
