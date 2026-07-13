package kvdb

import (
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// TestGetAddressSecretImportedPrivateKey verifies that an imported private-key
// address returns its encrypted private key and no script.
func TestGetAddressSecretImportedPrivateKey(t *testing.T) {
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

	secret, err := store.GetAddressSecret(t.Context(),
		db.GetAddressSecretQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, secret)
	require.NotEmpty(t, secret.EncryptedPrivKey,
		"imported private-key address must expose encrypted priv key")
	require.Empty(t, secret.EncryptedScript)
	require.Equal(t, uint32(0), secret.AddressID)
}

// TestGetAddressSecretImportedScript verifies that an imported taproot script
// address returns its encrypted script and no private key.
func TestGetAddressSecretImportedScript(t *testing.T) {
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

	_, err = store.NewImportedAddress(t.Context(),
		db.NewImportedAddressParams{
			WalletID:        0,
			AddressType:     db.TaprootPubKey,
			ScriptPubKey:    pkScript,
			EncryptedScript: encryptedScript,
		},
	)
	require.NoError(t, err)

	secret, err := store.GetAddressSecret(t.Context(),
		db.GetAddressSecretQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, secret)
	require.NotEmpty(t, secret.EncryptedScript,
		"imported script address must expose encrypted script")
	require.Empty(t, secret.EncryptedPrivKey)
	require.Equal(t, uint32(0), secret.AddressID)
}

// TestGetAddressSecretUnknownScript verifies that a script the wallet does not
// own maps to ErrSecretNotFound.
func TestGetAddressSecretUnknownScript(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	// Build a standard P2WPKH script for a key the wallet has never seen.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pkScript := p2wpkhScript(t, privKey, addrStore.ChainParams())

	_, err = store.GetAddressSecret(t.Context(),
		db.GetAddressSecretQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.ErrorIs(t, err, db.ErrSecretNotFound)
}

// TestGetAddressSecretByIDUnsupported verifies that kvdb rejects the
// AddressID selector, since it has no synthetic per-address row identity.
func TestGetAddressSecretByIDUnsupported(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	id := uint32(1)
	_, err := store.GetAddressSecret(t.Context(),
		db.GetAddressSecretQuery{
			WalletID:  0,
			AddressID: &id,
		},
	)
	require.ErrorIs(t, err, db.ErrSecretNotFound)
}

// p2wpkhScript builds a P2WPKH output script for the given key on chainParams.
func p2wpkhScript(t *testing.T, privKey *btcec.PrivateKey,
	chainParams *chaincfg.Params) []byte {

	t.Helper()

	pubKeyHash := address.Hash160(privKey.PubKey().SerializeCompressed())
	addr, err := address.NewAddressWitnessPubKeyHash(pubKeyHash, chainParams)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return pkScript
}
