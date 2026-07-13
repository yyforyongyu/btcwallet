package db

import "errors"

// ErrAccountSecretUnavailable is returned when a backend does not expose
// store-side account secret material through AccountStore.
var ErrAccountSecretUnavailable = errors.New("account secret unavailable")

// Validate checks whether a GetAccountSecretQuery identifies exactly one
// account selector among AccountID, Name, and AccountNumber.
func (query GetAccountSecretQuery) Validate() error {
	var selectors int
	if query.AccountID != nil {
		selectors++
	}

	if query.Name != nil {
		selectors++
	}

	if query.AccountNumber != nil {
		selectors++
	}

	if selectors != 1 {
		return ErrInvalidQuery
	}

	return nil
}
