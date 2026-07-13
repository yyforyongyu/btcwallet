package db

// Validate checks that a GetAddressSecretQuery identifies its target with
// exactly one selector: either AddressID or ScriptPubKey, but not both and
// not neither.
func (query GetAddressSecretQuery) Validate() error {
	hasID := query.AddressID != nil
	hasSPK := len(query.ScriptPubKey) > 0

	if hasID == hasSPK {
		return ErrInvalidQuery
	}

	return nil
}
