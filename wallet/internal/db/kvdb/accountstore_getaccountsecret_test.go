package kvdb

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// bip84Scope is the db.KeyScope used by the account-secret tests.
var bip84Scope = db.KeyScope{
	Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
	Coin:    waddrmgr.KeyScopeBIP0084.Coin,
}

// TestGetAccountSecretDerived verifies that a derived account returns its
// encrypted private key, plaintext public key, name, number, and the
// side-bucket master fingerprint, resolvable both by account number and by
// name.
func TestGetAccountSecretDerived(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	const name = "fp-derived"

	deriveFn := fingerprintDeriveFnFixture(t, mgr)
	info, err := store.CreateDerivedAccount(t.Context(),
		db.CreateDerivedAccountParams{
			Scope: bip84Scope,
			Name:  name,
		},
		deriveFn,
	)
	require.NoError(t, err)
	require.NotNil(t, info.AccountNumber)

	number := *info.AccountNumber

	// Look up by AccountNumber.
	byNumber, err := store.GetAccountSecret(t.Context(),
		db.GetAccountSecretQuery{
			Scope:         bip84Scope,
			AccountNumber: &number,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, byNumber)
	require.NotNil(t, byNumber.EncryptedPrivateKey,
		"derived account must expose encrypted private key")
	require.Equal(t, number, byNumber.AccountNumber)
	require.Equal(t, name, byNumber.AccountName)
	require.Equal(t, info.PublicKey, byNumber.PublicKey)
	require.Equal(t, testFingerprintValue, byNumber.MasterKeyFingerprint)
	require.Equal(t, bip84Scope, byNumber.Scope)

	// Look up by AccountID; kvdb maps it to the same durable account
	// number, so it must return the identical secret.
	byID, err := store.GetAccountSecret(t.Context(),
		db.GetAccountSecretQuery{
			Scope:     bip84Scope,
			AccountID: &number,
		},
	)
	require.NoError(t, err)
	require.Equal(t, byNumber, byID)

	// Look up by Name.
	acctName := name
	byName, err := store.GetAccountSecret(t.Context(),
		db.GetAccountSecretQuery{
			Scope: bip84Scope,
			Name:  &acctName,
		},
	)
	require.NoError(t, err)
	require.Equal(t, byNumber, byName)
}

// TestGetAccountSecretImportedHasNoPrivateKey verifies that a watch-only
// imported account resolves to a secret with a nil encrypted private key while
// still returning the public key and master fingerprint.
func TestGetAccountSecretImportedHasNoPrivateKey(t *testing.T) {
	t.Parallel()

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	const name = "imported-xpub"

	seed := bytes.Repeat([]byte{0xBB}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)
	masterPub, err := master.Neuter()
	require.NoError(t, err)

	_, err = store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			Scope:             bip84Scope,
			Name:              name,
			MasterFingerprint: 0xDEADBEEF,
			PublicKey:         []byte(masterPub.String()),
		},
	)
	require.NoError(t, err)

	// Imported accounts have no public account number, so they are looked
	// up by name.
	acctName := name
	secret, err := store.GetAccountSecret(t.Context(),
		db.GetAccountSecretQuery{
			Scope: bip84Scope,
			Name:  &acctName,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, secret)
	require.Nil(t, secret.EncryptedPrivateKey,
		"imported account must not expose a private key")
	require.Equal(t, name, secret.AccountName)
	require.Equal(t, []byte(masterPub.String()), secret.PublicKey)
	require.Equal(t, uint32(0xDEADBEEF), secret.MasterKeyFingerprint)
}

// TestGetAccountSecretNotFound verifies that querying an absent account
// returns ErrAccountNotFound both by number and by name.
func TestGetAccountSecretNotFound(t *testing.T) {
	t.Parallel()

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	missingNumber := uint32(99)
	_, err := store.GetAccountSecret(t.Context(),
		db.GetAccountSecretQuery{
			Scope:         bip84Scope,
			AccountNumber: &missingNumber,
		},
	)
	require.ErrorIs(t, err, db.ErrAccountNotFound)

	missingName := "does-not-exist"
	_, err = store.GetAccountSecret(t.Context(),
		db.GetAccountSecretQuery{
			Scope: bip84Scope,
			Name:  &missingName,
		},
	)
	require.ErrorIs(t, err, db.ErrAccountNotFound)
}

// TestGetAccountSecretInvalidQuery verifies that a query without exactly one
// selector is rejected before any store access.
func TestGetAccountSecretInvalidQuery(t *testing.T) {
	t.Parallel()

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	_, err := store.GetAccountSecret(t.Context(),
		db.GetAccountSecretQuery{
			Scope: bip84Scope,
		},
	)
	require.ErrorIs(t, err, db.ErrInvalidQuery)
}
