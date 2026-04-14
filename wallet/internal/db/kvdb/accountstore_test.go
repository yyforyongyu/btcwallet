package kvdb

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// TestGetAccountSuccess verifies that kvdb.Store adapts legacy account metadata
// into the db-native account view.
func TestGetAccountSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	props := createLegacyAccount(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084, "reader",
	)

	name := "reader"
	infoByName, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		WalletID: 0,
		Scope:    db.KeyScope(waddrmgr.KeyScopeBIP0084),
		Name:     &name,
	})
	require.NoError(t, err)
	require.Equal(t, props.AccountNumber, infoByName.AccountNumber)
	require.Equal(t, name, infoByName.AccountName)
	require.Equal(t, db.DerivedAccount, infoByName.Origin)

	accountNum := props.AccountNumber
	infoByNumber, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		WalletID:      0,
		Scope:         db.KeyScope(waddrmgr.KeyScopeBIP0084),
		AccountNumber: &accountNum,
	})
	require.NoError(t, err)
	require.Equal(t, infoByName.AccountName, infoByNumber.AccountName)
}

// TestCreateDerivedAccountSuccess verifies that kvdb.Store creates one derived
// account through the legacy account-manager path.
func TestCreateDerivedAccountSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	err := walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		return addrStore.Unlock(ns, testPrivPass)
	})
	require.NoError(t, err)

	info, err := store.CreateDerivedAccount(t.Context(),
		db.CreateDerivedAccountParams{
			WalletID: 0,
			Scope:    db.KeyScope(waddrmgr.KeyScopeBIP0084),
			Name:     "created",
		},
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), info.AccountNumber)
	require.Equal(t, "created", info.AccountName)
	require.Equal(t, db.DerivedAccount, info.Origin)
}

// TestListAccountsFilters verifies that kvdb.Store lists and filters accounts
// through the legacy account manager path.
func TestListAccountsFilters(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	createLegacyAccount(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084, "shared",
	)
	createLegacyAccount(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0086, "shared",
	)

	scope := db.KeyScope(waddrmgr.KeyScopeBIP0084)
	accounts, err := store.ListAccounts(t.Context(), db.ListAccountsQuery{
		WalletID: 0,
		Scope:    &scope,
	})
	require.NoError(t, err)
	require.NotEmpty(t, accounts)
	require.Equal(t, scope, accounts[0].KeyScope)

	name := "shared"
	filtered, err := store.ListAccounts(t.Context(), db.ListAccountsQuery{
		WalletID: 0,
		Name:     &name,
	})
	require.NoError(t, err)
	require.Len(t, filtered, 2)
	require.Equal(
		t, db.KeyScope(waddrmgr.KeyScopeBIP0084), filtered[0].KeyScope,
	)
	require.Equal(
		t, db.KeyScope(waddrmgr.KeyScopeBIP0086), filtered[1].KeyScope,
	)
}

// TestRenameAccountSuccess verifies that kvdb.Store renames a legacy account
// by name.
func TestRenameAccountSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	createLegacyAccount(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084, "before",
	)

	err := store.RenameAccount(t.Context(), db.RenameAccountParams{
		WalletID: 0,
		Scope:    db.KeyScope(waddrmgr.KeyScopeBIP0084),
		OldName:  "before",
		NewName:  "after",
	})
	require.NoError(t, err)

	name := "after"
	info, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		WalletID: 0,
		Scope:    db.KeyScope(waddrmgr.KeyScopeBIP0084),
		Name:     &name,
	})
	require.NoError(t, err)
	require.Equal(t, "after", info.AccountName)
}

// TestImportAccountSuccess verifies that kvdb.Store imports one watch-only
// account through the legacy account-manager path.
func TestImportAccountSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)
	accountKey := testAccountPubKey(t, waddrmgr.KeyScopeBIP0084)
	name := "watch-only"
	schema := db.ScopeAddrMap[db.KeyScopeBIP0084]

	props, err := store.ImportAccount(t.Context(), db.ImportAccountParams{
		WalletID:          0,
		Name:              name,
		Scope:             db.KeyScope(waddrmgr.KeyScopeBIP0084),
		AccountKey:        accountKey,
		MasterFingerprint: 101,
		AddrSchema:        &schema,
		DryRun:            false,
	})
	require.NoError(t, err)
	require.Equal(t, name, props.AccountName)
	require.Equal(t, db.DerivedAccount, props.Origin)

	info, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		WalletID: 0,
		Scope:    db.KeyScope(waddrmgr.KeyScopeBIP0084),
		Name:     &name,
	})
	require.NoError(t, err)
	require.Equal(t, name, info.AccountName)
	require.Equal(t, db.DerivedAccount, info.Origin)
}

// TestImportAccountDryRun verifies that kvdb.Store validates a watch-only
// import without persisting it.
func TestImportAccountDryRun(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)
	accountKey := testAccountPubKey(t, waddrmgr.KeyScopeBIP0084)
	name := "dry-run"
	schema := db.ScopeAddrMap[db.KeyScopeBIP0084]

	props, err := store.ImportAccount(t.Context(), db.ImportAccountParams{
		WalletID:          0,
		Name:              name,
		Scope:             db.KeyScope(waddrmgr.KeyScopeBIP0084),
		AccountKey:        accountKey,
		MasterFingerprint: 202,
		AddrSchema:        &schema,
		DryRun:            true,
	})
	require.NoError(t, err)
	require.Equal(t, name, props.AccountName)

	_, err = store.GetAccount(t.Context(), db.GetAccountQuery{
		WalletID: 0,
		Scope:    db.KeyScope(waddrmgr.KeyScopeBIP0084),
		Name:     &name,
	})
	require.ErrorIs(t, err, db.ErrAccountNotFound)
}

func createLegacyAccount(t *testing.T, dbConn walletdb.DB,
	addrStore *waddrmgr.Manager, scope waddrmgr.KeyScope,
	name string) *waddrmgr.AccountProperties {

	t.Helper()

	manager, err := addrStore.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	var props *waddrmgr.AccountProperties

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		return addrStore.Unlock(ns, testPrivPass)
	})
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		accountNum, err := manager.NewAccount(ns, name)
		if err != nil {
			return err
		}

		props, err = manager.AccountProperties(ns, accountNum)

		return err
	})
	require.NoError(t, err)

	return props
}

func testAccountPubKey(t *testing.T,
	scope waddrmgr.KeyScope) *hdkeychain.ExtendedKey {

	t.Helper()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	key, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	path := []uint32{
		scope.Purpose + hdkeychain.HardenedKeyStart,
		scope.Coin + hdkeychain.HardenedKeyStart,
		hdkeychain.HardenedKeyStart,
	}

	for _, child := range path {
		key, err = key.Derive(child)
		require.NoError(t, err)
	}

	key, err = key.Neuter()
	require.NoError(t, err)

	return key
}
