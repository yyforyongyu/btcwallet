package db

// nextListWalletsQuery returns the query for the next page.
func nextListWalletsQuery(q ListWalletsQuery, cursor uint32) ListWalletsQuery {
	q.Page = q.Page.WithAfter(cursor)

	return q
}
