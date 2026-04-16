package kvdb

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// TestGetManagedPubKeyAddressByPathSuccess verifies that kvdb.Store adapts one
// BIP32 path into the legacy managed pubkey address view used by signer flows.
func TestGetManagedPubKeyAddressByPathSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	addr, _, path := createDerivedPubKeyAddr(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084,
	)

	managedAddr, err := store.GetManagedPubKeyAddressByPath(
		t.Context(), db.SignerPathQuery{
			WalletID:       0,
			Scope:          db.KeyScope(waddrmgr.KeyScopeBIP0084),
			DerivationPath: path,
		},
	)
	require.NoError(t, err)
	require.Equal(
		t, addr.EncodeAddress(), managedAddr.Address().EncodeAddress(),
	)
}

// TestGetManagedPubKeyAddressSuccess verifies that kvdb.Store resolves one
// known address into the legacy managed pubkey address view used by signer
// callers.
func TestGetManagedPubKeyAddressSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	addr, _, _ := createDerivedPubKeyAddr(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084,
	)

	managedAddr, err := store.GetManagedPubKeyAddress(
		t.Context(), db.SignerAddressQuery{
			WalletID: 0,
			Address:  addr.EncodeAddress(),
		},
	)
	require.NoError(t, err)
	require.Equal(
		t, addr.EncodeAddress(), managedAddr.Address().EncodeAddress(),
	)
}

// TestGetManagedPubKeyAddressNotPubKey verifies that signer address lookup
// rejects managed addresses that do not expose pubkey operations.
func TestGetManagedPubKeyAddressNotPubKey(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)
	addr := importTaprootScriptAddr(t, store)

	_, err := store.GetManagedPubKeyAddress(
		t.Context(), db.SignerAddressQuery{
			WalletID: 0,
			Address:  addr.EncodeAddress(),
		},
	)
	require.ErrorIs(t, err, db.ErrNotManagedPubKeyAddress)
}

// TestGetManagedPubKeyAddressByPathFetchManagerError verifies that signer path
// lookups propagate scoped-manager lookup failures.
func TestGetManagedPubKeyAddressByPathFetchManagerError(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)

	store := NewStore(dbConn, nil, &testLegacyAddrStore{})

	_, err := store.GetManagedPubKeyAddressByPath(
		t.Context(), db.SignerPathQuery{
			WalletID: 0,
			Scope:    db.KeyScope(waddrmgr.KeyScopeBIP0084),
		},
	)
	require.ErrorIs(t, err, errTestAccountNotFound)
}

func createDerivedPubKeyAddr(t *testing.T, dbConn walletdb.DB,
	addrStore *waddrmgr.Manager, scope waddrmgr.KeyScope) (
	btcutil.Address, waddrmgr.ManagedPubKeyAddress, waddrmgr.DerivationPath) {

	t.Helper()

	manager, err := addrStore.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	var (
		addr       btcutil.Address
		pubKeyAddr waddrmgr.ManagedPubKeyAddress
	)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		addr, err = manager.NewAddress(ns, waddrmgr.DefaultAccountName, false)
		if err != nil {
			return err
		}

		managedAddr, err := addrStore.Address(ns, addr)
		if err != nil {
			return err
		}

		pubKeyAddr, err = kvdbManagedPubKeyAddress(managedAddr)
		if err != nil {
			return err
		}

		return nil
	})
	require.NoError(t, err)

	_, path, ok := pubKeyAddr.DerivationInfo()
	require.True(t, ok)

	return addr, pubKeyAddr, path
}

func importTaprootScriptAddr(t *testing.T, store *Store) btcutil.Address {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	script, err := txscript.NewScriptBuilder().
		AddData(privKey.PubKey().SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	leaf := txscript.NewTapLeaf(txscript.BaseLeafVersion, script)
	tapscript := waddrmgr.Tapscript{
		Type:         waddrmgr.TapscriptTypeFullTree,
		Leaves:       []txscript.TapLeaf{leaf},
		ControlBlock: &txscript.ControlBlock{InternalKey: privKey.PubKey()},
	}

	addr, err := store.ImportTaprootScript(
		t.Context(), db.ImportTaprootScriptParams{
			WalletID:       0,
			Tapscript:      tapscript,
			SyncedTo:       waddrmgr.BlockStamp{Height: 1},
			WitnessVersion: 1,
			IsSecretScript: false,
		},
	)
	require.NoError(t, err)

	return addr
}
