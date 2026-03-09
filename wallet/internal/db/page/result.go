package page

// Result holds one page of items returned by a paginated list query. It
// maintains an invariant: LastCursor is nil if and only if Items is empty. The
// meaning of HasMore depends on the Request's early-exhaustion mode; see
// Request.WithEarlyExhaustion for details.
type Result[T any, C any] struct {
	// Items contain the results for this page. It may be empty on the last
	// page.
	Items []T

	// LastCursor is the cursor of the last item in Items. It is nil when Items
	// is empty. It is never nil when Items is non-empty, so it may be safely
	// dereferenced after checking Items. Pass this to Request.WithCursor to
	// resume from this page.
	LastCursor *C

	// HasMore reports whether more items exist beyond this page.
	//
	// When early-exhaustion is off (default), HasMore is true whenever Items is
	// non-empty. It does not guarantee more items exist; the caller must fetch
	// the next page to confirm the list is exhausted.
	//
	// When early-exhaustion is on, HasMore is true only when the backend
	// confirmed at least one more item exists past the current page. HasMore
	// false on a non-empty page means this is the last page.
	HasMore bool
}
