package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGetAccountSecretQueryValidate verifies account-secret lookups must use
// exactly one account selector among AccountID, Name, and AccountNumber.
func TestGetAccountSecretQueryValidate(t *testing.T) {
	t.Parallel()

	accountID := uint32(3)
	name := defaultAccountName
	accountNumber := uint32(7)

	tests := []struct {
		name    string
		query   GetAccountSecretQuery
		wantErr error
	}{
		{
			name:  "id selector",
			query: GetAccountSecretQuery{AccountID: &accountID},
		},
		{
			name:  "name selector",
			query: GetAccountSecretQuery{Name: &name},
		},
		{
			name: "number selector",
			query: GetAccountSecretQuery{
				AccountNumber: &accountNumber,
			},
		},
		{
			name:    "no selector",
			query:   GetAccountSecretQuery{},
			wantErr: ErrInvalidQuery,
		},
		{
			name: "id and name selectors",
			query: GetAccountSecretQuery{
				AccountID: &accountID,
				Name:      &name,
			},
			wantErr: ErrInvalidQuery,
		},
		{
			name: "name and number selectors",
			query: GetAccountSecretQuery{
				Name:          &name,
				AccountNumber: &accountNumber,
			},
			wantErr: ErrInvalidQuery,
		},
		{
			name: "all selectors",
			query: GetAccountSecretQuery{
				AccountID:     &accountID,
				Name:          &name,
				AccountNumber: &accountNumber,
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
