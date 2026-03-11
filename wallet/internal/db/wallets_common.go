package db

// nextListWalletsQuery returns the query for the next page by advancing the
// cursor to the provided cursor value. page.Iter calls this only after
// confirming HasMore is true and LastCursor is non-nil.
func nextListWalletsQuery(q ListWalletsQuery, cursor uint32) ListWalletsQuery {
	q.Page = q.Page.WithCursor(cursor)

	return q
}
