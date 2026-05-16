// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// errUnsupportedTestDoubleMethod is returned if a test unexpectedly exercises
// unsupported managed pubkey methods.
var errUnsupportedTestDoubleMethod = errors.New(
	"unsupported test double method",
)

// TestAddressStoreNewDerivedAddress verifies that kvdb.Store creates derived
// addresses through the legacy address manager.
func TestAddressStoreNewDerivedAddress(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)
	props := createLegacyAccount(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084, "addr",
	)

	info, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    0,
			AccountName: "addr",
			Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
		},
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), info.ID)
	require.Equal(t, db.DerivedAccount, info.Origin)
	require.Equal(t, db.WitnessPubKey, info.AddrType)
	require.Equal(t, "addr", info.AccountName)
	require.Equal(t, props.AccountNumber, info.AccountID)
	require.NotEmpty(t, info.ScriptPubKey)
	require.NotEmpty(t, info.PubKey)

	got, err := store.GetAddress(
		t.Context(), db.GetAddressQuery{
			WalletID:     0,
			ScriptPubKey: info.ScriptPubKey,
		},
	)
	require.NoError(t, err)
	require.Equal(t, info, got)
}

// TestAddressStoreImportedPublicKeyIsWatchOnly verifies that imported public
// keys are marked watch-only instead of relying only on imported origin.
func TestAddressStoreImportedPublicKeyIsWatchOnly(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	pubKeyBytes := pubKey.SerializeCompressed()
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKeyBytes), addrStore.ChainParams(),
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	info, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     0,
			Scope:        db.KeyScope(waddrmgr.KeyScopeBIP0084),
			AddressType:  db.WitnessPubKey,
			ScriptPubKey: pkScript,
			PubKey:       pubKeyBytes,
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.ImportedAccount, info.Origin)
	require.Equal(t, db.WitnessPubKey, info.AddrType)
	require.Equal(t, pkScript, info.ScriptPubKey)
	require.Equal(t, pubKeyBytes, info.PubKey)
	require.True(t, info.IsWatchOnly)

	got, err := store.GetAddress(
		t.Context(), db.GetAddressQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.True(t, got.IsWatchOnly)
}

// TestAddressStoreImportedPrivateKeyIsSpendable verifies that legacy imported
// private keys are not marked watch-only.
func TestAddressStoreImportedPrivateKeyIsSpendable(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	unlockAddrStore(t, dbConn, addrStore)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	wif, err := btcutil.NewWIF(privKey, addrStore.ChainParams(), false)
	require.NoError(t, err)

	manager, err := addrStore.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)

	var pkScript []byte

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		managedAddr, err := manager.ImportPrivateKey(ns, wif, nil)
		if err != nil {
			return err
		}

		pkScript, err = txscript.PayToAddrScript(managedAddr.Address())

		return err
	})
	require.NoError(t, err)

	got, err := store.GetAddress(
		t.Context(), db.GetAddressQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.False(t, got.IsWatchOnly)
	require.Len(t, got.PubKey, len(privKey.PubKey().SerializeUncompressed()))
}

// TestAddressStoreImportedPublicKeyRejectsMismatch verifies that kvdb rejects
// imported public-key requests when legacy import output does not match the
// requested type or script.
func TestAddressStoreImportedPublicKeyRejectsMismatch(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		addrType   db.AddressType
		scriptFunc func(*testing.T, []byte, *waddrmgr.Manager) []byte
	}{
		{
			name:     "type mismatch",
			addrType: db.PubKeyHash,
			scriptFunc: func(t *testing.T, script []byte,
				_ *waddrmgr.Manager) []byte {

				t.Helper()

				return script
			},
		},
		{
			name:     "script mismatch",
			addrType: db.WitnessPubKey,
			scriptFunc: func(t *testing.T, _ []byte,
				addrStore *waddrmgr.Manager) []byte {

				t.Helper()

				otherPrivKey, err := btcec.NewPrivateKey()
				require.NoError(t, err)

				otherPubKey := otherPrivKey.PubKey().SerializeCompressed()
				otherAddr, err := btcutil.NewAddressWitnessPubKeyHash(
					btcutil.Hash160(otherPubKey),
					addrStore.ChainParams(),
				)
				require.NoError(t, err)

				otherScript, err := txscript.PayToAddrScript(
					otherAddr,
				)
				require.NoError(t, err)

				return otherScript
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dbConn, cleanup := newTestDB(t)
			t.Cleanup(cleanup)

			addrStore := newSpendableAddrMgr(t, dbConn)
			store := NewStore(dbConn, nil, addrStore)

			privKey, err := btcec.NewPrivateKey()
			require.NoError(t, err)

			pubKeyBytes := privKey.PubKey().SerializeCompressed()
			addr, err := btcutil.NewAddressWitnessPubKeyHash(
				btcutil.Hash160(pubKeyBytes), addrStore.ChainParams(),
			)
			require.NoError(t, err)

			actualScript, err := txscript.PayToAddrScript(addr)
			require.NoError(t, err)

			_, err = store.NewImportedAddress(
				t.Context(), db.NewImportedAddressParams{
					WalletID: 0,
					Scope: db.KeyScope(
						waddrmgr.KeyScopeBIP0084,
					),
					AddressType: tc.addrType,
					ScriptPubKey: tc.scriptFunc(
						t, actualScript, addrStore,
					),
					PubKey: pubKeyBytes,
				},
			)
			require.ErrorIs(t, err, errImportedAddressMismatch)
		})
	}
}

// TestAddressStoreImportTaprootScript verifies that kvdb.Store imports taproot
// script metadata through the legacy address manager while preserving the store
// level script marker.
func TestAddressStoreImportTaprootScript(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	tapscript, pkScript := testTaprootScript(t, addrStore)
	encodedScript, err := waddrmgr.EncodeTaprootScript(&tapscript)
	require.NoError(t, err)
	encryptedScript, err := addrStore.Encrypt(
		waddrmgr.CKTPublic, encodedScript,
	)
	require.NoError(t, err)

	info, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:        0,
			Scope:           db.KeyScope(waddrmgr.KeyScopeBIP0086),
			AddressType:     db.TaprootPubKey,
			ScriptPubKey:    pkScript,
			EncryptedScript: encryptedScript,
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.ImportedAccount, info.Origin)
	require.Equal(t, db.TaprootPubKey, info.AddrType)
	require.True(t, info.HasScript)
	require.Equal(t, pkScript, info.ScriptPubKey)

	got, err := store.GetAddress(
		t.Context(), db.GetAddressQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.True(t, got.HasScript)
	require.Equal(t, db.TaprootPubKey, got.AddrType)
}

// TestManagedAddressIsWatchOnlyUnsupportedPubKey verifies that unsupported
// managed public-key address implementations are reported explicitly.
func TestManagedAddressIsWatchOnlyUnsupportedPubKey(t *testing.T) {
	t.Parallel()

	isWatchOnly, err := managedAddressIsWatchOnly(
		false, unsupportedManagedPubKeyAddress{},
	)
	require.ErrorContains(t, err, "unsupported managed pubkey address")
	require.False(t, isWatchOnly)
}

type unsupportedManagedPubKeyAddress struct {
	waddrmgr.ManagedAddress
}

// Imported reports that the unsupported test double is imported.
func (unsupportedManagedPubKeyAddress) Imported() bool {
	return true
}

// PubKey returns no public key for the unsupported test double.
func (unsupportedManagedPubKeyAddress) PubKey() *btcec.PublicKey {
	return nil
}

// ExportPubKey returns no public key for the unsupported test double.
func (unsupportedManagedPubKeyAddress) ExportPubKey() string {
	return ""
}

// PrivKey returns no private key for the unsupported test double.
func (unsupportedManagedPubKeyAddress) PrivKey() (*btcec.PrivateKey, error) {
	return nil, errUnsupportedTestDoubleMethod
}

// ExportPrivKey returns no private key for the unsupported test double.
func (unsupportedManagedPubKeyAddress) ExportPrivKey() (*btcutil.WIF, error) {
	return nil, errUnsupportedTestDoubleMethod
}

// DerivationInfo returns no derivation path for the unsupported test double.
func (unsupportedManagedPubKeyAddress) DerivationInfo() (waddrmgr.KeyScope,
	waddrmgr.DerivationPath, bool) {

	return waddrmgr.KeyScope{}, waddrmgr.DerivationPath{}, false
}

// unlockAddrStore unlocks the legacy address manager for private-key imports.
func unlockAddrStore(t *testing.T, dbConn walletdb.DB,
	addrStore *waddrmgr.Manager) {

	t.Helper()

	err := walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		return addrStore.Unlock(ns, testPrivPass)
	})
	require.NoError(t, err)
}

// testTaprootScript returns a tapscript and its P2TR output script.
func testTaprootScript(t *testing.T,
	addrStore *waddrmgr.Manager) (waddrmgr.Tapscript, []byte) {

	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	script, err := txscript.NewScriptBuilder().
		AddData(pubKey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	leaf := txscript.NewTapLeaf(txscript.BaseLeafVersion, script)
	tree := txscript.AssembleTaprootScriptTree(leaf)
	rootHash := tree.RootNode.TapHash()
	taprootKey := txscript.ComputeTaprootOutputKey(pubKey, rootHash[:])
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(taprootKey), addrStore.ChainParams(),
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return waddrmgr.Tapscript{
		Type: waddrmgr.TapscriptTypeFullTree,
		ControlBlock: &txscript.ControlBlock{
			InternalKey: pubKey,
		},
		Leaves: []txscript.TapLeaf{leaf},
	}, pkScript
}
