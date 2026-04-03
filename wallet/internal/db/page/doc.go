// Package page provides cursor-based pagination primitives for SQL-backed
// stores.
//
// A Request carries the page limit together with an optional resume cursor. A
// Result carries the returned items plus the next cursor when another page may
// exist.
//
// Store implementations are expected to fetch `limit + 1` rows, trim the extra
// lookahead row with BuildResult, and then expose iteration through Iter.
package page
