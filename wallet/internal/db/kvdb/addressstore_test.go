package kvdb

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

var errTestAccountNotFound = errors.New("test account not found")

// TestGetAddressDetailsSuccess verifies that kvdb.Store adapts legacy address
// details into the db-native address metadata view used by the wallet.
func TestGetAddressDetailsSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)

	addr, pkScript := newTestAddressScript(t)
	addrStore := &testLegacyAddrStore{
		chainParams: &chaincfg.RegressionNetParams,
		detailsByAddr: map[string]testLegacyAddressDetails{
			addr.String(): {
				spendable: true,
				account:   "default",
				addrType:  waddrmgr.WitnessPubKey,
			},
		},
	}

	store := NewStore(dbConn, nil, addrStore)

	spendable, account, addrType, err := store.GetAddressDetails(
		t.Context(), db.GetAddressDetailsQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.True(t, spendable)
	require.Equal(t, "default", account)
	require.Equal(t, db.WitnessPubKey, addrType)
}

// TestNewDerivedAddressSuccess verifies that kvdb.Store routes derived-address
// creation through the legacy address manager.
func TestNewDerivedAddressSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	info, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    0,
			AccountName: waddrmgr.DefaultAccountName,
			Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
			Change:      false,
		}, nil,
	)
	require.NoError(t, err)
	require.NotEmpty(t, info.ScriptPubKey)
	require.Equal(t, db.DerivedAccount, info.Origin)
}

// TestFindUnusedAddressFiltersAndSkipsUsed verifies that kvdb.Store scans one
// account, filters by branch, and skips used addresses.
func TestFindUnusedAddressFiltersAndSkipsUsed(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	manager, err := addrStore.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)

	var (
		firstExternal  btcutil.Address
		secondExternal btcutil.Address
		changeAddr     btcutil.Address
	)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		firstExternal, err = manager.NewAddress(
			ns, waddrmgr.DefaultAccountName, false,
		)
		if err != nil {
			return err
		}

		changeAddr, err = manager.NewAddress(
			ns, waddrmgr.DefaultAccountName, true,
		)
		if err != nil {
			return err
		}

		secondExternal, err = manager.NewAddress(
			ns, waddrmgr.DefaultAccountName, false,
		)
		if err != nil {
			return err
		}

		return addrStore.MarkUsed(ns, firstExternal)
	})
	require.NoError(t, err)

	unusedAddr, err := store.FindUnusedAddress(t.Context(),
		db.FindUnusedAddressQuery{
			WalletID:    0,
			AccountName: waddrmgr.DefaultAccountName,
			Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
			Change:      false,
		},
	)
	require.NoError(t, err)
	require.Equal(t, secondExternal.EncodeAddress(), unusedAddr.EncodeAddress())

	unusedChange, err := store.FindUnusedAddress(t.Context(),
		db.FindUnusedAddressQuery{
			WalletID:    0,
			AccountName: waddrmgr.DefaultAccountName,
			Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
			Change:      true,
		},
	)
	require.NoError(t, err)
	require.Equal(t, changeAddr.EncodeAddress(), unusedChange.EncodeAddress())
}

// TestGetManagedAddressSuccess verifies that kvdb.Store returns the legacy
// managed-address view for one known address.
func TestGetManagedAddressSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	manager, err := addrStore.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)

	var addr btcutil.Address

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		addr, err = manager.NewAddress(ns, waddrmgr.DefaultAccountName, false)

		return err
	})
	require.NoError(t, err)

	managedAddr, err := store.GetManagedAddress(t.Context(),
		db.GetManagedAddressQuery{WalletID: 0, Address: addr.EncodeAddress()},
	)
	require.NoError(t, err)
	require.Equal(
		t, addr.EncodeAddress(), managedAddr.Address().EncodeAddress(),
	)
}

// TestListAddressesSuccess verifies that kvdb.Store lists account addresses as
// db-native rows.
func TestListAddressesSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	manager, err := addrStore.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		_, err = manager.NewAddress(ns, waddrmgr.DefaultAccountName, false)
		if err != nil {
			return err
		}

		_, err = manager.NewAddress(ns, waddrmgr.DefaultAccountName, true)

		return err
	})
	require.NoError(t, err)

	req, err := page.NewRequest[uint32](2)
	require.NoError(t, err)

	addresses, err := store.ListAddresses(t.Context(), db.ListAddressesQuery{
		WalletID:    0,
		AccountName: waddrmgr.DefaultAccountName,
		Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
		Page:        req,
	})
	require.NoError(t, err)
	require.Len(t, addresses.Items, 2)
	require.NotEmpty(t, addresses.Items[0].ScriptPubKey)
	require.NotEmpty(t, addresses.Items[1].ScriptPubKey)
}

// TestImportPublicKeySuccess verifies that kvdb.Store adapts the legacy public
// key import path.
func TestImportPublicKeySuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	addr, err := store.ImportPublicKey(t.Context(), db.ImportPublicKeyParams{
		WalletID:         0,
		Scope:            db.KeyScope(waddrmgr.KeyScopeBIP0084),
		SerializedPubKey: privKey.PubKey().SerializeCompressed(),
	})
	require.NoError(t, err)
	require.NotNil(t, addr)

	managedAddr, err := store.GetManagedAddress(t.Context(),
		db.GetManagedAddressQuery{WalletID: 0, Address: addr.EncodeAddress()},
	)
	require.NoError(t, err)
	require.True(t, managedAddr.Imported())
}

// TestImportTaprootScriptSuccess verifies that kvdb.Store adapts the legacy
// taproot script import path.
func TestImportTaprootScriptSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

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

	addr, err := store.ImportTaprootScript(t.Context(),
		db.ImportTaprootScriptParams{
			WalletID:       0,
			Tapscript:      tapscript,
			SyncedTo:       waddrmgr.BlockStamp{Height: 1},
			WitnessVersion: 1,
			IsSecretScript: false,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, addr)

	managedAddr, err := store.GetManagedAddress(t.Context(),
		db.GetManagedAddressQuery{WalletID: 0, Address: addr.EncodeAddress()},
	)
	require.NoError(t, err)
	require.True(t, managedAddr.Imported())
}

type testLegacyAddressDetails struct {
	spendable bool
	account   string
	addrType  waddrmgr.AddressType
}

type testLegacyAddrStore struct {
	chainParams   *chaincfg.Params
	currentHeight int32
	detailsByAddr map[string]testLegacyAddressDetails
	accountByAddr map[string]uint32
}

func (s *testLegacyAddrStore) ChainParams() *chaincfg.Params {
	return s.chainParams
}

func (s *testLegacyAddrStore) SyncedTo() waddrmgr.BlockStamp {
	return waddrmgr.BlockStamp{Height: s.currentHeight}
}

func (s *testLegacyAddrStore) FetchScopedKeyManager(
	_ waddrmgr.KeyScope) (waddrmgr.AccountStore, error) {

	return nil, errTestAccountNotFound
}

func (s *testLegacyAddrStore) Address(_ walletdb.ReadBucket,
	_ btcutil.Address) (waddrmgr.ManagedAddress, error) {

	return nil, errTestAccountNotFound
}

func (s *testLegacyAddrStore) AddressDetails(_ walletdb.ReadBucket,
	addr btcutil.Address) (bool, string, waddrmgr.AddressType) {

	details, ok := s.detailsByAddr[addr.String()]
	if !ok {
		return false, legacyUnknownAccountName, 0
	}

	return details.spendable, details.account, details.addrType
}

func (s *testLegacyAddrStore) AddrAccount(_ walletdb.ReadBucket,
	addr btcutil.Address) (waddrmgr.AccountStore, uint32, error) {

	account, ok := s.accountByAddr[addr.String()]
	if !ok {
		return nil, 0, errTestAccountNotFound
	}

	return nil, account, nil
}

func newTestAddressScript(t *testing.T) (btcutil.Address, []byte) {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	addr, err := btcutil.NewAddressPubKey(
		privKey.PubKey().SerializeCompressed(), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return addr, pkScript
}
