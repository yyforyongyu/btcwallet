package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGetAddressSecretQueryValidate verifies address-secret lookups must use
// exactly one selector: either AddressID or ScriptPubKey.
func TestGetAddressSecretQueryValidate(t *testing.T) {
	t.Parallel()

	addressID := uint32(5)

	tests := []struct {
		name    string
		query   GetAddressSecretQuery
		wantErr error
	}{
		{
			name:  "address ID selector",
			query: GetAddressSecretQuery{AddressID: &addressID},
		},
		{
			name: "script pubkey selector",
			query: GetAddressSecretQuery{
				ScriptPubKey: []byte{0x01, 0x02, 0x03},
			},
		},
		{
			name:    "no selector",
			query:   GetAddressSecretQuery{},
			wantErr: ErrInvalidQuery,
		},
		{
			name: "both selectors",
			query: GetAddressSecretQuery{
				AddressID:    &addressID,
				ScriptPubKey: []byte{0x01, 0x02, 0x03},
			},
			wantErr: ErrInvalidQuery,
		},
		{
			name: "empty script pubkey",
			query: GetAddressSecretQuery{
				ScriptPubKey: []byte{},
			},
			wantErr: ErrInvalidQuery,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.query.Validate()
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}
