// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

var (
	// errNoSyncBucket is an error that is returned when the sync bucket is
	// not found.
	errNoSyncBucket = newError(ErrDatabase, "sync bucket not found", nil)
)

// ErrorCode identifies a kind of error.
type ErrorCode int

// These constants are used to identify a specific Error.
const (
	// ErrDatabase indicates a database error.
	ErrDatabase ErrorCode = iota

	// ErrAccountNotFound is returned when a requesting account is not found.
	ErrAccountNotFound
)

// Error identifies a wallet error. It has an error code and a descriptive
// message.
type Error struct {
	Code ErrorCode
	Desc string
	Err  error
}

// Error satisfies the error interface and prints human-readable errors.
func (e Error) Error() string {
	return e.Desc
}

// Unwrap returns the underlying error, if any.
func (e Error) Unwrap() error {
	return e.Err
}

// newError creates an Error given a set of arguments.
func newError(c ErrorCode, desc string, err error) Error {
	return Error{Code: c, Desc: desc, Err: err}
}