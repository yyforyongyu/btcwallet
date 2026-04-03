package page

// Result holds one page of items returned by a paginated list query.
//
// When HasNext is true, Next is the cursor to pass to the next request. When
// HasNext is false, Next is ignored.
type Result[T any, C any] struct {
	// Items contains the results for this page.
	Items []T

	// Next is the cursor for the next page.
	Next C

	// HasNext reports whether another page may be fetched.
	HasNext bool
}
