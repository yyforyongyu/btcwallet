// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet_test

import (
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// TestAccountIdentitySelectorValidate verifies that semantic account selectors
// accept exactly one portable identity and reject ambiguous or empty shapes.
func TestAccountIdentitySelectorValidate(t *testing.T) {
	accountName := "imported-xpub"
	accountNumber := wallet.AccountNumber(0)

	tests := []struct {
		name      string
		selector  wallet.AccountSelector
		wantError bool
	}{
		{
			name: "accepts name",
			selector: wallet.AccountSelector{
				KeyScope:    waddrmgr.KeyScopeBIP0084,
				AccountName: &accountName,
			},
		},
		{
			name: "accepts present zero number",
			selector: wallet.AccountSelector{
				KeyScope:      waddrmgr.KeyScopeBIP0084,
				AccountNumber: &accountNumber,
			},
		},
		{
			name: "rejects neither",
			selector: wallet.AccountSelector{
				KeyScope: waddrmgr.KeyScopeBIP0084,
			},
			wantError: true,
		},
		{
			name: "rejects both",
			selector: wallet.AccountSelector{
				KeyScope:      waddrmgr.KeyScopeBIP0084,
				AccountName:   &accountName,
				AccountNumber: &accountNumber,
			},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.selector.Validate()

			require.Equal(t, test.wantError, err != nil)
		})
	}
}

// TestAccountIdentityOptionalValues verifies that external callers can
// distinguish absent identity values from present-zero values using pointers.
func TestAccountIdentityOptionalValues(t *testing.T) {
	var absentAccountNumber *wallet.AccountNumber
	accountNumber := wallet.AccountNumber(0)
	presentAccountNumber := &accountNumber

	var absentFingerprint *wallet.MasterFingerprint
	fingerprint := wallet.MasterFingerprint(0)
	presentFingerprint := &fingerprint

	require.Nil(t, absentAccountNumber)
	require.NotNil(t, presentAccountNumber)
	require.Equal(t, wallet.AccountNumber(0), *presentAccountNumber)
	require.Nil(t, absentFingerprint)
	require.NotNil(t, presentFingerprint)
	require.Equal(t, wallet.MasterFingerprint(0), *presentFingerprint)
}
