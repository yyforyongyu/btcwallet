// Package page provides cursor-based pagination primitives for SQL-backed
// stores.
//
// # Core types
//
// A [Request] carries the parameters for a single page fetch: page size,
// an optional cursor that identifies where the previous page ended, and
// an optional early-exhaustion flag. The zero value requests the first
// page at [DefaultPageSize].
//
// A [Result] carries the items returned by one fetch together with
// [Result.LastCursor] and [Result.HasMore]. Pass LastCursor back to
// [Request.WithCursor] to advance to the next page.
//
// # Two exhaustion modes
//
// The package supports two strategies for detecting the end of a list:
//
// Deferred exhaustion (default): each query fetches exactly Size rows.
// HasMore is true for every non-empty page. End-of-list is confirmed only
// after a subsequent fetch returns zero rows. This adds one extra
// round-trip at the end but gives a strong consistency guarantee —
// exhaustion is concluded only after observing an empty result.
//
// Early exhaustion ([Request.WithEarlyExhaustion]): the query fetches
// Size+1 rows internally and returns at most Size. If the extra row
// exists, HasMore is true; if not, this is the last page — no extra
// round-trip needed. The tradeoff is a small per-query overhead and a
// weaker guarantee: rows inserted after the query completes may not be
// reflected.
//
// # Iterating
//
// [Iter] wraps a fetch function in a standard [iter.Seq2] that pages
// transparently until the list is exhausted or the caller breaks early.
// It propagates fetch errors and respects context cancellation through
// the fetchPage callback.
//
// # Store integration
//
// Stores typically translate [Request.Cursor] into an optional backend
// query parameter, fetch [Request.QueryLimit] rows with a single ordered
// SQL query, map the raw rows to domain items, and then call
// [BuildResult] to derive [Result.LastCursor] and [Result.HasMore].
package page
