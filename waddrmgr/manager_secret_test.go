// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// masterKeyParams returns copies of the manager's current public and private
// master-key marshalled parameters, in that order. It is used by the
// ChangePassphrases tests to detect whether the in-memory master keys have been
// swapped.
func masterKeyParams(mgr *Manager) ([]byte, []byte) {
	mgr.mtx.RLock()
	defer mgr.mtx.RUnlock()

	return mgr.masterKeyPub.Marshal(), mgr.masterKeyPriv.Marshal()
}

// TestChangePassphrasesPublicOnly verifies that a public-only change rotates
// the public master key, leaves the private master key untouched, and that the
// new public passphrase is accepted on a subsequent open.
func TestChangePassphrasesPublicOnly(t *testing.T) {
	t.Parallel()

	// Arrange: a freshly created manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	oldPub, oldPriv := masterKeyParams(mgr)

	// Act: change only the public passphrase.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		return mgr.ChangePassphrases(ns, ChangePassphrasesParams{
			ChangePublic: true,
			PublicOld:    pubPassphrase,
			PublicNew:    pubPassphrase2,
			Config:       fastScrypt,
		})
	})
	require.NoError(t, err)

	// Assert: the public master key changed while the private one did not.
	newPub, newPriv := masterKeyParams(mgr)
	require.NotEqual(t, oldPub, newPub)
	require.Equal(t, oldPriv, newPriv)

	// Assert: the new public passphrase can re-derive the public master key.
	secretKey := snacl.SecretKey{Key: &snacl.CryptoKey{}}
	secretKey.Parameters = mgr.masterKeyPub.Parameters
	require.NoError(t, secretKey.DeriveKey(&pubPassphrase2))
	secretKey.Zero()
}

// TestChangePassphrasesPrivateOnly verifies that a private-only change rotates
// the private master key, leaves the public master key untouched, and that the
// wallet can be unlocked with the new private passphrase.
func TestChangePassphrasesPrivateOnly(t *testing.T) {
	t.Parallel()

	// Arrange: a freshly created manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	oldPub, oldPriv := masterKeyParams(mgr)

	// Act: change only the private passphrase.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		return mgr.ChangePassphrases(ns, ChangePassphrasesParams{
			ChangePrivate: true,
			PrivateOld:    privPassphrase,
			PrivateNew:    privPassphrase2,
			Config:        fastScrypt,
		})
	})
	require.NoError(t, err)

	// Assert: the private master key changed while the public one did not.
	newPub, newPriv := masterKeyParams(mgr)
	require.Equal(t, oldPub, newPub)
	require.NotEqual(t, oldPriv, newPriv)

	// Assert: the wallet unlocks with the new private passphrase.
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		return mgr.Unlock(ns, privPassphrase2)
	})
	require.NoError(t, err)
	require.NoError(t, mgr.Lock())
}

// TestChangePassphrasesBoth verifies that changing both passphrases in a single
// call rotates both master keys atomically and that both new passphrases are
// accepted afterwards.
func TestChangePassphrasesBoth(t *testing.T) {
	t.Parallel()

	// Arrange: a freshly created manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	oldPub, oldPriv := masterKeyParams(mgr)

	// Act: change both passphrases at once.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		return mgr.ChangePassphrases(ns, ChangePassphrasesParams{
			ChangePublic:  true,
			PublicOld:     pubPassphrase,
			PublicNew:     pubPassphrase2,
			ChangePrivate: true,
			PrivateOld:    privPassphrase,
			PrivateNew:    privPassphrase2,
			Config:        fastScrypt,
		})
	})
	require.NoError(t, err)

	// Assert: both master keys changed.
	newPub, newPriv := masterKeyParams(mgr)
	require.NotEqual(t, oldPub, newPub)
	require.NotEqual(t, oldPriv, newPriv)

	// Assert: the new public passphrase re-derives the public master key.
	secretKey := snacl.SecretKey{Key: &snacl.CryptoKey{}}
	secretKey.Parameters = mgr.masterKeyPub.Parameters
	require.NoError(t, secretKey.DeriveKey(&pubPassphrase2))
	secretKey.Zero()

	// Assert: the wallet unlocks with the new private passphrase.
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		return mgr.Unlock(ns, privPassphrase2)
	})
	require.NoError(t, err)
	require.NoError(t, mgr.Lock())
}

// TestChangePassphrasesWrongOldPublic verifies that a wrong old public
// passphrase is rejected before any state is mutated, even when a valid private
// change is requested in the same call.
func TestChangePassphrasesWrongOldPublic(t *testing.T) {
	t.Parallel()

	// Arrange: a freshly created manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	oldPub, oldPriv := masterKeyParams(mgr)

	// Act: request a change with a bogus old public passphrase but an
	// otherwise valid private change; the whole operation must be rejected.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		return mgr.ChangePassphrases(ns, ChangePassphrasesParams{
			ChangePublic:  true,
			PublicOld:     []byte("bogus"),
			PublicNew:     pubPassphrase2,
			ChangePrivate: true,
			PrivateOld:    privPassphrase,
			PrivateNew:    privPassphrase2,
			Config:        fastScrypt,
		})
	})

	// Assert: the wrong-passphrase error is returned and neither master key
	// was mutated.
	require.True(
		t, checkManagerError(t, "wrong old public", err,
			ErrWrongPassphrase),
	)

	newPub, newPriv := masterKeyParams(mgr)
	require.Equal(t, oldPub, newPub)
	require.Equal(t, oldPriv, newPriv)

	// Assert: the original passphrases still work.
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		return mgr.Unlock(ns, privPassphrase)
	})
	require.NoError(t, err)
	require.NoError(t, mgr.Lock())
}

// TestChangePassphrasesWrongOldPrivate verifies that a wrong old private
// passphrase is rejected and that a validly requested public change in the same
// call is NOT applied (atomic all-or-nothing).
func TestChangePassphrasesWrongOldPrivate(t *testing.T) {
	t.Parallel()

	// Arrange: a freshly created manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	oldPub, oldPriv := masterKeyParams(mgr)

	// Act: request a valid public change but a bogus old private passphrase.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		return mgr.ChangePassphrases(ns, ChangePassphrasesParams{
			ChangePublic:  true,
			PublicOld:     pubPassphrase,
			PublicNew:     pubPassphrase2,
			ChangePrivate: true,
			PrivateOld:    []byte("bogus"),
			PrivateNew:    privPassphrase2,
			Config:        fastScrypt,
		})
	})

	// Assert: the wrong-passphrase error is returned and neither master key
	// was mutated, proving the public change did not leak through.
	require.True(
		t, checkManagerError(t, "wrong old private", err,
			ErrWrongPassphrase),
	)

	newPub, newPriv := masterKeyParams(mgr)
	require.Equal(t, oldPub, newPub)
	require.Equal(t, oldPriv, newPriv)

	// Assert: the original public passphrase still re-derives the key.
	secretKey := snacl.SecretKey{Key: &snacl.CryptoKey{}}
	secretKey.Parameters = mgr.masterKeyPub.Parameters
	require.NoError(t, secretKey.DeriveKey(&pubPassphrase))
	secretKey.Zero()
}

// TestChangePassphrasesWatchOnly verifies that requesting a private passphrase
// change on a watching-only manager is rejected with ErrWatchingOnly.
func TestChangePassphrasesWatchOnly(t *testing.T) {
	t.Parallel()

	// Arrange: a freshly created manager converted to watching-only.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		return mgr.ConvertToWatchingOnly(ns)
	})
	require.NoError(t, err)

	// Act: attempt to change the private passphrase.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		return mgr.ChangePassphrases(ns, ChangePassphrasesParams{
			ChangePrivate: true,
			PrivateOld:    privPassphrase,
			PrivateNew:    privPassphrase2,
			Config:        fastScrypt,
		})
	})

	// Assert: the watching-only error is returned.
	require.True(
		t, checkManagerError(t, "watch-only", err, ErrWatchingOnly),
	)
}

// TestChangePassphrasesDeferredSwap verifies the atomicity contract of the
// in-memory swap: the new master keys are only installed on a successful
// commit. It asserts that the swap has not happened yet while the transaction
// is still open, and that rolling the transaction back leaves the old keys in
// place (a stand-in for a commit failure, since bdb exposes no commit-failure
// hook).
//
// NOTE: This relies on OnCommit only firing on a successful commit; a rolled
// back transaction must never install the staged keys.
func TestChangePassphrasesDeferredSwap(t *testing.T) {
	t.Parallel()

	// Arrange: a freshly created manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	oldPub, oldPriv := masterKeyParams(mgr)

	// Act + Assert (deferral): while still inside the transaction, the swap
	// must not have run yet, then force a rollback by returning an error.
	errBoom := &boomError{}
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := mgr.ChangePassphrases(
			ns, ChangePassphrasesParams{
				ChangePublic:  true,
				PublicOld:     pubPassphrase,
				PublicNew:     pubPassphrase2,
				ChangePrivate: true,
				PrivateOld:    privPassphrase,
				PrivateNew:    privPassphrase2,
				Config:        fastScrypt,
			},
		)
		if err != nil {
			return err
		}

		// The swap is registered via OnCommit, so the in-memory keys
		// must still be the old ones at this point.
		pendingPub, pendingPriv := masterKeyParams(mgr)
		require.Equal(t, oldPub, pendingPub)
		require.Equal(t, oldPriv, pendingPriv)

		// Force a rollback.
		return errBoom
	})
	require.ErrorIs(t, err, errBoom)

	// Assert: after the rollback the in-memory master keys are unchanged,
	// proving the staged keys were never installed.
	finalPub, finalPriv := masterKeyParams(mgr)
	require.Equal(t, oldPub, finalPub)
	require.Equal(t, oldPriv, finalPriv)

	// Assert: the original passphrases still work on disk and in memory.
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		return mgr.Unlock(ns, privPassphrase)
	})
	require.NoError(t, err)
	require.NoError(t, mgr.Lock())
}

// boomError is a sentinel error used to force a transaction rollback in the
// deferred-swap test.
type boomError struct{}

// Error implements the error interface.
func (*boomError) Error() string { return "boom" }

// TestAccountSecretDerived verifies that AccountSecret returns the persisted
// encrypted private key, the correct account public key, name, and imported
// flag for a normal derived (default) account.
func TestAccountSecretDerived(t *testing.T) {
	t.Parallel()

	// Arrange: a created, unlocked manager and its BIP0044 scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	scopedMgr := fetchBIP44Scoped(t, mgr)

	var (
		gotPub       *hdkeychain.ExtendedKey
		gotEnc       []byte
		gotFinger    uint32
		gotName      string
		gotImported  bool
		expectedPriv *hdkeychain.ExtendedKey
	)

	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		// Unlock so we can decrypt the returned ciphertext for
		// verification, then read the account secret.
		err := mgr.Unlock(ns, privPassphrase)
		if err != nil {
			return err
		}

		gotPub, gotEnc, gotFinger, gotName, gotImported, err =
			scopedMgr.AccountSecret(ns, DefaultAccountNum)
		if err != nil {
			return err
		}

		// Derive the expected account private key straight from the
		// seed for cross-checking the returned ciphertext.
		expectedPriv = deriveTestAccountPrivKey(t)

		return nil
	})
	require.NoError(t, err)

	// Assert: name/imported flag and a non-nil ciphertext. Default account
	// rows do not persist a fingerprint, so it must be zero.
	require.Equal(t, DefaultAccountName, gotName)
	require.False(t, gotImported)
	require.Equal(t, uint32(0), gotFinger)
	require.NotNil(t, gotPub)
	require.NotEmpty(t, gotEnc)

	// Assert: the returned public key matches the neutered expected key.
	expectedPub, err := expectedPriv.Neuter()
	require.NoError(t, err)
	require.Equal(t, expectedPub.String(), gotPub.String())

	// Assert: decrypting the returned ciphertext with the crypto private
	// key yields the expected account private key. This proves the stored
	// ciphertext was returned verbatim (and never re-derived).
	mgr.mtx.RLock()
	serialized, err := mgr.cryptoKeyPriv.Decrypt(gotEnc)
	mgr.mtx.RUnlock()
	require.NoError(t, err)
	require.Equal(t, expectedPriv.String(), string(serialized))
}

// TestAccountSecretWatchOnly verifies that AccountSecret returns a nil
// encrypted private key and the stored fingerprint for a watch-only imported
// account.
func TestAccountSecretWatchOnly(t *testing.T) {
	t.Parallel()

	// Arrange: a created manager and its BIP0044 scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	scopedMgr := fetchBIP44Scoped(t, mgr)

	// Import a watch-only account with a known fingerprint.
	acctKey := deriveTestAccountKey(t)
	require.NotNil(t, acctKey)

	acctKeyPub, err := acctKey.Neuter()
	require.NoError(t, err)

	const wantFingerprint = uint32(0xdeadbeef)

	var account uint32

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		account, err = scopedMgr.NewAccountWatchingOnly(
			ns, "watch-only", acctKeyPub, wantFingerprint, nil,
		)

		return err
	})
	require.NoError(t, err)

	// Act: read the account secret for the watch-only account.
	var (
		gotPub      *hdkeychain.ExtendedKey
		gotEnc      []byte
		gotFinger   uint32
		gotName     string
		gotImported bool
	)

	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		gotPub, gotEnc, gotFinger, gotName, gotImported, err =
			scopedMgr.AccountSecret(ns, account)

		return err
	})
	require.NoError(t, err)

	// Assert: no private key, correct fingerprint/name/imported flag, and a
	// public key that matches the imported one.
	require.Nil(t, gotEnc)
	require.Equal(t, wantFingerprint, gotFinger)
	require.Equal(t, "watch-only", gotName)
	require.True(t, gotImported)
	require.NotNil(t, gotPub)
	require.Equal(t, acctKeyPub.String(), gotPub.String())
}

// TestAccountSecretNotFound verifies that AccountSecret returns
// ErrAccountNotFound for an account that does not exist.
func TestAccountSecretNotFound(t *testing.T) {
	t.Parallel()

	// Arrange: a created manager and its BIP0044 scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	scopedMgr := fetchBIP44Scoped(t, mgr)

	// Act: read a non-existent account.
	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		_, _, _, _, _, err := scopedMgr.AccountSecret(ns, 9999)

		return err
	})

	// Assert: the account-not-found error is returned.
	require.True(
		t, checkManagerError(t, "missing account", err,
			ErrAccountNotFound),
	)
}

// TestManagedAddressSecretPubKey verifies that ManagedAddressSecret returns the
// stored encrypted private key (and no script) for an imported pubkey address.
func TestManagedAddressSecretPubKey(t *testing.T) {
	t.Parallel()

	// Arrange: a created, unlocked manager and its BIP0044 scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	scopedMgr := fetchBIP44Scoped(t, mgr)

	// A fixed private key we can import and later cross-check.
	privKeyBytes := hexToBytes(
		"c27d6581b92785834b381fa697c4b0ffc4574b495743722e0acb7601b1b68b99",
	)
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	require.NoError(t, err)

	var (
		importedAddr address.Address
		gotPriv      []byte
		gotScript    []byte
	)

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := mgr.Unlock(ns, privPassphrase)
		if err != nil {
			return err
		}

		managed, err := scopedMgr.ImportPrivateKey(
			ns, wif, &BlockStamp{},
		)
		if err != nil {
			return err
		}

		importedAddr = managed.Address()

		// Act: read the address secret.
		gotPriv, gotScript, err = scopedMgr.ManagedAddressSecret(
			ns, importedAddr,
		)

		return err
	})
	require.NoError(t, err)

	// Assert: a private-key ciphertext is returned and no script.
	require.NotEmpty(t, gotPriv)
	require.Nil(t, gotScript)

	// Assert: the ciphertext decrypts to the imported private key.
	mgr.mtx.RLock()
	serialized, err := mgr.cryptoKeyPriv.Decrypt(gotPriv)
	mgr.mtx.RUnlock()
	require.NoError(t, err)
	require.Equal(t, privKeyBytes, serialized)
}

// TestManagedAddressSecretScript verifies that ManagedAddressSecret returns the
// stored encrypted script (and no private key) for an imported script address.
func TestManagedAddressSecretScript(t *testing.T) {
	t.Parallel()

	// Arrange: a created, unlocked manager and its BIP0044 scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	scopedMgr := fetchBIP44Scoped(t, mgr)

	script := hexToBytes(
		"51210373c717acd6b1d4c9d92e5c5c6c62c1c1c1c1c1c1c1c1c1c1c1c1c" +
			"1c1c1c1c1c151ae",
	)

	var (
		importedAddr address.Address
		gotPriv      []byte
		gotScript    []byte
	)

	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := mgr.Unlock(ns, privPassphrase)
		if err != nil {
			return err
		}

		managed, err := scopedMgr.ImportScript(ns, script, &BlockStamp{})
		if err != nil {
			return err
		}

		importedAddr = managed.Address()

		// Act: read the address secret.
		gotPriv, gotScript, err = scopedMgr.ManagedAddressSecret(
			ns, importedAddr,
		)

		return err
	})
	require.NoError(t, err)

	// Assert: a script ciphertext is returned and no private key.
	require.Nil(t, gotPriv)
	require.NotEmpty(t, gotScript)

	// Assert: the ciphertext decrypts to the imported script.
	mgr.mtx.RLock()
	serialized, err := mgr.cryptoKeyScript.Decrypt(gotScript)
	mgr.mtx.RUnlock()
	require.NoError(t, err)
	require.Equal(t, script, serialized)
}

// TestManagedAddressSecretNotFound verifies that ManagedAddressSecret returns
// the not-found error for an address that was never added to the manager,
// keeping it distinguishable from a found-but-secretless address.
func TestManagedAddressSecretNotFound(t *testing.T) {
	t.Parallel()

	// Arrange: a created manager and its BIP0044 scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	scopedMgr := fetchBIP44Scoped(t, mgr)

	// A valid P2PKH address that was never imported.
	unknown, err := address.NewAddressPubKeyHash(
		hexToBytes("0000000000000000000000000000000000000000"),
		&chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	// Act: look up the unknown address.
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		_, _, err := scopedMgr.ManagedAddressSecret(ns, unknown)

		return err
	})

	// Assert: the address-not-found error is returned.
	require.True(
		t, checkManagerError(t, "missing address", err,
			ErrAddressNotFound),
	)
}

// fetchBIP44Scoped is a small helper that returns the concrete BIP0044 scoped
// key manager for the given root manager.
func fetchBIP44Scoped(t *testing.T, mgr *Manager) *ScopedKeyManager {
	t.Helper()

	acctStore, err := mgr.FetchScopedKeyManager(KeyScopeBIP0044)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	return scopedMgr
}

// deriveTestAccountPrivKey derives the default BIP0044 account extended private
// key straight from the test seed so tests can cross-check the ciphertext
// returned by AccountSecret.
func deriveTestAccountPrivKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	require.NoError(t, err)

	scopeKey, err := deriveCoinTypeKey(masterKey, KeyScopeBIP0044)
	require.NoError(t, err)

	accountKey, err := deriveAccountKey(scopeKey, 0)
	require.NoError(t, err)

	return accountKey
}
