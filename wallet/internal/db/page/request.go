package page

const (
	// DefaultPageSize is the default number of items returned in a page.
	DefaultPageSize = 100

	// MaxPageSize is the maximum number of items that can be returned in a
	// page. SQL queries that implement early-exhaustion lookahead may receive
	// MaxPageSize+1 as the page limit.
	MaxPageSize = 1000
)

// Request holds the parameters for a paginated list query. The zero value is
// valid and requests the first page at DefaultPageSize. All With* methods
// return a modified copy (value-type immutability).
//
// Fields are unexported so that callers must use the With* methods and
// accessor functions. This design preserves the normalization of size (zero
// maps to DefaultPageSize via Size()) and ensures consistency across all
// page operations.
type Request[C any] struct {
	// size is the maximum number of items to return per page.
	size uint32

	// cursor is the pagination cursor from the previous page.
	// Nil means the first page.
	cursor *C

	// earlyExhaustion controls whether LastCursor and HasMore use deferred
	// (false, default) or early (true) semantics.
	earlyExhaustion bool
}

// Size returns the normalized requested page size for this request. A size of
// zero returns DefaultPageSize. A size greater than MaxPageSize is clamped to
// MaxPageSize.
func (r Request[C]) Size() uint32 {
	if r.size == 0 {
		return DefaultPageSize
	}

	if r.size > MaxPageSize {
		return MaxPageSize
	}

	return r.size
}

// QueryLimit returns the number of rows the SQL query should fetch. When early
// exhaustion is enabled, it returns Size+1 to allow HasMore detection without
// an extra round-trip. Otherwise, it returns Size.
func (r Request[C]) QueryLimit() uint32 {
	if r.earlyExhaustion {
		return r.Size() + 1
	}

	return r.Size()
}

// WithSize returns a copy of request with size replaced. The size is not
// validated here; normalization (zero -> DefaultPageSize, over MaxPageSize ->
// MaxPageSize) happens in Size() and QueryLimit(). A caller passing 0 or a
// large value will not see an error, the value will just be normalized later.
func (r Request[C]) WithSize(size uint32) Request[C] {
	r.size = size

	return r
}

// Cursor returns the pagination cursor from the previous page.
// A nil return value means the first page is being requested.
func (r Request[C]) Cursor() *C {
	return r.cursor
}

// WithCursor returns a copy of the request with the cursor replaced. Calling
// this on a zero-value Request produces a request for the second page (the page
// after this cursor). It takes the cursor by value to avoid the caller
// retaining a pointer into the Request.
func (r Request[C]) WithCursor(cursor C) Request[C] {
	r.cursor = &cursor

	return r
}

// EarlyExhaustion reports whether the request uses early-exhaustion
// mode. See WithEarlyExhaustion for a full description.
func (r Request[C]) EarlyExhaustion() bool {
	return r.earlyExhaustion
}

// WithEarlyExhaustion enables early exhaustion detection for the request.
//
// Default behavior (disabled):
//   - Provides a stronger guarantee: exhaustion is only concluded after an
//     empty result, so it reflects a stable and complete view of the dataset
//     at the time of the final fetch.
//   - The query fetches exactly Size rows.
//   - HasMore is true whenever the page is non-empty.
//   - End of iteration is only known after an extra fetch that returns no rows.
//   - Zero extra work per query.
//   - Requires one additional round-trip at the end.
//
// Early exhaustion enabled:
//   - HasMore = false reflects the state at query time only. Rows inserted
//     after the query may not be observed, so exhaustion is not a strict
//     completeness guarantee under concurrent writes.
//   - The query fetches Size+1 rows internally and returns at most Size rows.
//   - If an extra row is present, HasMore = true.
//   - If not, HasMore = false, meaning this is the last page.
//   - Avoids the final round-trip.
//   - Adds a very small overhead per query due to fetching one extra row.
func (r Request[C]) WithEarlyExhaustion() Request[C] {
	r.earlyExhaustion = true

	return r
}

// BuildResult assembles a page.Result from a slice of items already fetched by
// the caller. It uses r.Size and r.EarlyExhaustion to determine HasMore and
// LastCursor. The toCursor function is called on the last item of the possibly
// trimmed slice.
//
// An empty slice always returns an empty result regardless of mode.
//
// When early exhaustion is disabled (default):
//   - Any non-empty slice sets HasMore to true and LastCursor to the
//     cursor of the last item.
//
// When early exhaustion is enabled:
//   - If len(items) is greater than Size, it trims to Size and sets
//     HasMore to true.
//   - If len(items) is non-empty and less than or equal to Size,
//     HasMore is false.
func BuildResult[Cursor, Item any](r Request[Cursor], items []Item,
	toCursor func(Item) Cursor) Result[Item, Cursor] {

	if len(items) == 0 {
		return Result[Item, Cursor]{Items: items}
	}

	if !r.EarlyExhaustion() {
		// Deferred exhaustion: any non-empty page signals "maybe more data
		// exists."
		// The actual end-of-list is confirmed only after a later fetch returns
		// zero rows. This guarantees a stable, complete view at the final fetch
		// at the cost of one extra round-trip.
		last := items[len(items)-1]
		cursor := toCursor(last)

		return Result[Item, Cursor]{
			Items:      items,
			LastCursor: &cursor,
			HasMore:    true,
		}
	}

	pageSize := r.Size()

	// Early exhaustion: fetch queries retrieve Size+1 rows. If the extra row
	// exists, it signals "more data available." If not, we have the entire
	// final page. Trimming to pageSize avoids over-fetching in the result,
	// using the extra row purely as a lookahead signal to avoid a final
	// round-trip. This trades off a small per-query overhead and weaker
	// consistency for reduced round-trips.
	hasMore := len(items) > int(pageSize)
	if hasMore {
		items = items[:int(pageSize)]
	}

	last := items[len(items)-1]
	cursor := toCursor(last)

	return Result[Item, Cursor]{
		Items:      items,
		LastCursor: &cursor,
		HasMore:    hasMore,
	}
}
