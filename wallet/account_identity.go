// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

var errInvalidAccountSelector = errors.New(
	"exactly one of account name or account number must be provided",
)

// AccountNumber is the BIP44 account index within a key scope. A nil pointer
// means the account has no BIP44 number, while a non-nil zero identifies
// account zero.
type AccountNumber uint32

// MasterFingerprint is the BIP32 master key fingerprint. A nil pointer means
// the fingerprint is absent, while a non-nil zero is a present-zero
// fingerprint.
type MasterFingerprint uint32

// AccountSelector identifies an account by its portable wallet semantics. A
// valid selector contains a key scope and exactly one of AccountName or
// AccountNumber.
type AccountSelector struct {
	// KeyScope identifies the derivation scope that owns the account.
	KeyScope waddrmgr.KeyScope

	// AccountName selects an account by its name when non-nil.
	AccountName *string

	// AccountNumber selects a wallet-derived account by its BIP44 account
	// number when non-nil.
	AccountNumber *AccountNumber
}

// Validate verifies that exactly one of AccountName or AccountNumber is set.
// It performs no backend access.
func (s AccountSelector) Validate() error {
	if (s.AccountName == nil) == (s.AccountNumber == nil) {
		return errInvalidAccountSelector
	}

	return nil
}
