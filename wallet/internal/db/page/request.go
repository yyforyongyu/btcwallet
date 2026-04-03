package page

const (
	// DefaultLimit is the default number of items returned in a page.
	DefaultLimit = 100

	// MaxLimit is the maximum number of items that can be returned in a page.
	// Store implementations may fetch MaxLimit+1 rows internally to detect
	// whether another page exists.
	MaxLimit = 1000
)

// Request holds the parameters for a paginated list query.
//
// The zero value is valid and requests the first page at DefaultLimit.
// When HasAfter is false, After is ignored.
type Request[C any] struct {
	// Limit is the requested number of items to return.
	Limit uint32

	// After is the cursor from the previous page.
	After C

	// HasAfter reports whether After should be applied.
	HasAfter bool
}

// EffectiveLimit returns the normalized requested page size.
//
// A zero limit uses DefaultLimit. A limit greater than MaxLimit is clamped to
// MaxLimit.
func (r Request[C]) EffectiveLimit() uint32 {
	return effectiveLimit(r.Limit)
}

// WithAfter returns a copy of the request with the resume cursor set.
func (r Request[C]) WithAfter(after C) Request[C] {
	r.After = after
	r.HasAfter = true

	return r
}

// BuildResult assembles a Result from rows already fetched by the caller.
//
// The caller should pass the requested page limit, not the database fetch limit.
// BuildResult trims any `limit+1` lookahead row, derives the next cursor from
// the last retained item, and reports whether another page exists.
func BuildResult[T any, C any](items []T, limit uint32,
	nextOf func(T) C) Result[T, C] {

	if len(items) == 0 {
		return Result[T, C]{Items: items}
	}

	limit = effectiveLimit(limit)
	if len(items) <= int(limit) {
		return Result[T, C]{Items: items}
	}

	items = items[:int(limit)]
	last := items[len(items)-1]

	return Result[T, C]{
		Items:   items,
		Next:    nextOf(last),
		HasNext: true,
	}
}

// effectiveLimit normalizes a raw requested limit.
func effectiveLimit(limit uint32) uint32 {
	switch {
	case limit == 0:
		return DefaultLimit

	case limit > MaxLimit:
		return MaxLimit

	default:
		return limit
	}
}
