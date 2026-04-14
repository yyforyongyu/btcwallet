// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func hardenedKey(key uint32) uint32 {
	return key + hdkeychain.HardenedKeyStart
}

func ptr[T any](v T) *T {
	return &v
}

func deriveAcctPubKey(t *testing.T, root *hdkeychain.ExtendedKey,
	scope waddrmgr.KeyScope, paths ...uint32) *hdkeychain.ExtendedKey {

	t.Helper()

	path := []uint32{hardenedKey(scope.Purpose), hardenedKey(scope.Coin)}
	path = append(path, paths...)

	var (
		currentKey = root
		err        error
	)
	for _, pathPart := range path {
		currentKey, err = currentKey.Derive(pathPart)
		require.NoError(t, err)
	}

	// The Neuter() method checks the version and doesn't know any
	// non-standard methods. We need to convert them to standard, neuter,
	// then convert them back with the target extended public key version.
	pubVersionBytes := make([]byte, 4)
	copy(pubVersionBytes, chainParams.HDPublicKeyID[:])

	switch {
	case strings.HasPrefix(root.String(), "uprv"):
		binary.BigEndian.PutUint32(pubVersionBytes, uint32(
			waddrmgr.HDVersionTestNetBIP0049,
		))

	case strings.HasPrefix(root.String(), "vprv"):
		binary.BigEndian.PutUint32(pubVersionBytes, uint32(
			waddrmgr.HDVersionTestNetBIP0084,
		))
	}

	currentKey, err = currentKey.CloneWithVersion(
		chainParams.HDPrivateKeyID[:],
	)
	require.NoError(t, err)
	currentKey, err = currentKey.Neuter()
	require.NoError(t, err)
	currentKey, err = currentKey.CloneWithVersion(pubVersionBytes)
	require.NoError(t, err)

	return currentKey
}

const (
	// testAccountName is a constant for the account name used in the tests.
	testAccountName = "test"
)

// TestNewAccount tests that the NewAccount method works as expected.
func TestNewAccount(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// We'll start by creating a new account under the BIP0084 scope. We
	// expect this to succeed.
	scope := waddrmgr.KeyScopeBIP0084

	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("CanAddAccount").Return(nil).Once()
	deps.accountManager.On("NewAccount", mock.Anything, testAccountName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   testAccountName,
		}, nil).Once()

	account, err := w.NewAccount(t.Context(), scope, testAccountName)
	require.NoError(t, err, "unable to create new account")

	// The new account should be the first account created, so it should
	// have an index of 1.
	require.Equal(t, uint32(1), account.AccountNumber, "expected account 1")

	// We should be able to retrieve the account by its name.
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("LookupAccount", mock.Anything, testAccountName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   testAccountName,
		}, nil).Once()

	account2, err := w.GetAccount(t.Context(), scope, testAccountName)
	require.NoError(t, err, "unable to retrieve account")
	require.Equal(t, uint32(1), account2.AccountNumber)
	require.Equal(t, testAccountName, account2.AccountName)

	// We should not be able to create a new account with the same name.
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("CanAddAccount").Return(nil).Once()
	deps.accountManager.On("NewAccount", mock.Anything, testAccountName).
		Return(uint32(0), waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrDuplicateAccount,
		}).Once()

	_, err = w.NewAccount(t.Context(), scope, testAccountName)
	require.Error(t, err, "expected error when creating duplicate account")
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrDuplicateAccount),
		"expected ErrDuplicateAccount",
	)

	// We should not be able to create a new account when the wallet is
	// locked.
	deps.addrStore.On("Lock").Return(nil).Once()

	err = w.Lock(t.Context())
	require.NoError(t, err)

	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("CanAddAccount").
		Return(waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrLocked,
		}).Once()

	_, err = w.NewAccount(t.Context(), scope, "test2")
	require.Error(
		t, err, "expected error when creating account while wallet is "+
			"locked",
	)
}

// TestListAccounts tests that the ListAccounts method works as expected.
func TestListAccounts(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// We'll start by creating a new account under the BIP0084 scope.
	scope := waddrmgr.KeyScopeBIP0084
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("CanAddAccount").Return(nil).Once()
	deps.accountManager.On("NewAccount", mock.Anything, testAccountName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   testAccountName,
		}, nil).Once()

	_, err := w.NewAccount(t.Context(), scope, testAccountName)
	require.NoError(t, err, "unable to create new account")

	// Setup expectations for ListAccounts.
	deps.addrStore.On("ActiveScopedKeyManagers").
		Return([]waddrmgr.AccountStore{deps.accountManager}).Once()

	deps.accountManager.On("LastAccount", mock.Anything).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(0)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 0,
			AccountName:   "default",
		}, nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   testAccountName,
		}, nil).Once()

	// Now, we'll list all accounts and check that we have the default
	// account and the new account.
	accounts, err := w.ListAccounts(t.Context())
	require.NoError(t, err, "unable to list accounts")

	// We should have two accounts.
	require.Len(t, accounts.Accounts, 2, "expected two accounts")

	// The first account should be the default account.
	require.Equal(
		t, "default", accounts.Accounts[0].AccountName,
		"expected default account",
	)
	require.Equal(
		t, uint32(0), accounts.Accounts[0].AccountNumber,
		"expected default account number",
	)
	require.Equal(
		t, btcutil.Amount(0), accounts.Accounts[0].TotalBalance,
		"expected zero balance for default account",
	)

	// The new account should also be present.
	require.Equal(
		t, testAccountName, accounts.Accounts[1].AccountName,
		"expected new account",
	)
	require.Equal(
		t, uint32(1), accounts.Accounts[1].AccountNumber,
		"expected new account number",
	)
}

// TestListAccountsByScope tests that the ListAccountsByScope method works as
// expected.
func TestListAccountsByScope(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// We'll create two new accounts, one under the BIP0084 scope and one
	// under the BIP0049 scope.
	scopeBIP84 := waddrmgr.KeyScopeBIP0084
	accBIP84Name := "test bip84"

	deps.addrStore.On("FetchScopedKeyManager", scopeBIP84).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("CanAddAccount").Return(nil).Once()
	deps.accountManager.On("NewAccount", mock.Anything, accBIP84Name).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   accBIP84Name,
		}, nil).Once()

	_, err := w.NewAccount(t.Context(), scopeBIP84, accBIP84Name)
	require.NoError(t, err)

	scopeBIP49 := waddrmgr.KeyScopeBIP0049Plus
	accBIP49Name := "test bip49"

	deps.addrStore.On("FetchScopedKeyManager", scopeBIP49).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("CanAddAccount").Return(nil).Once()
	deps.accountManager.On("NewAccount", mock.Anything, accBIP49Name).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   accBIP49Name,
		}, nil).Once()

	_, err = w.NewAccount(t.Context(), scopeBIP49, accBIP49Name)
	require.NoError(t, err)

	// Mock expectations for ListAccountsByScope (BIP84).
	deps.addrStore.On("FetchScopedKeyManager", scopeBIP84).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("LastAccount", mock.Anything).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(0)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 0,
			AccountName:   "default",
		}, nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   accBIP84Name,
		}, nil).Once()

	// Now, we'll list the accounts for the BIP0084 scope and check that
	// we only get the default account for that scope and the new account we
	// created.
	accountsBIP84, err := w.ListAccountsByScope(t.Context(), scopeBIP84)
	require.NoError(t, err)

	// We should have two accounts, the default account and the new account.
	require.Len(t, accountsBIP84.Accounts, 2)

	// The first account should be the default account.
	require.Equal(t, "default", accountsBIP84.Accounts[0].AccountName)
	require.Equal(t, uint32(0), accountsBIP84.Accounts[0].AccountNumber)

	// The second account should be the new account.
	require.Equal(t, accBIP84Name, accountsBIP84.Accounts[1].AccountName)
	require.Equal(t, uint32(1), accountsBIP84.Accounts[1].AccountNumber)

	// Mock expectations for ListAccountsByScope (BIP49).
	deps.addrStore.On("FetchScopedKeyManager", scopeBIP49).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("LastAccount", mock.Anything).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(0)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 0,
			AccountName:   "default",
		}, nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   accBIP49Name,
		}, nil).Once()

	// Now, we'll do the same for the BIP0049 scope.
	accountsBIP49, err := w.ListAccountsByScope(t.Context(), scopeBIP49)
	require.NoError(t, err)

	// We should have two accounts, the default account and the new account.
	require.Len(t, accountsBIP49.Accounts, 2)

	// The first account should be the default account.
	require.Equal(t, "default", accountsBIP49.Accounts[0].AccountName)
	require.Equal(t, uint32(0), accountsBIP49.Accounts[0].AccountNumber)

	// The second account should be the new account.
	require.Equal(t, accBIP49Name, accountsBIP49.Accounts[1].AccountName)
	require.Equal(t, uint32(1), accountsBIP49.Accounts[1].AccountNumber)
}

// TestListAccountsByName tests that the ListAccountsByName method works as
// expected.
func TestListAccountsByName(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// We'll create two new accounts, one under the BIP0084 scope and one
	// under the BIP0049 scope.
	scopeBIP84 := waddrmgr.KeyScopeBIP0084
	accBIP84Name := "test bip84"

	deps.addrStore.On("FetchScopedKeyManager", scopeBIP84).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("CanAddAccount").Return(nil).Once()
	deps.accountManager.On("NewAccount", mock.Anything, accBIP84Name).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   accBIP84Name,
		}, nil).Once()

	_, err := w.NewAccount(t.Context(), scopeBIP84, accBIP84Name)
	require.NoError(t, err)

	scopeBIP49 := waddrmgr.KeyScopeBIP0049Plus
	accBIP49Name := "test bip49"

	deps.addrStore.On("FetchScopedKeyManager", scopeBIP49).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("CanAddAccount").Return(nil).Once()
	deps.accountManager.On("NewAccount", mock.Anything, accBIP49Name).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   accBIP49Name,
		}, nil).Once()

	_, err = w.NewAccount(t.Context(), scopeBIP49, accBIP49Name)
	require.NoError(t, err)

	// Mock expectations for ListAccountsByName (BIP84 name).
	deps.addrStore.On("ActiveScopedKeyManagers").
		Return([]waddrmgr.AccountStore{deps.accountManager}).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, accBIP84Name).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   accBIP84Name,
		}, nil).Once()

	// Now, we'll list the accounts for the BIP0084 scope and check that
	// we only get the default account for that scope and the new account we
	// created.
	accountsBIP84, err := w.ListAccountsByName(t.Context(), accBIP84Name)
	require.NoError(t, err)

	// We should have one account.
	require.Len(t, accountsBIP84.Accounts, 1)

	// The first account should be the new account.
	require.Equal(t, accBIP84Name, accountsBIP84.Accounts[0].AccountName)
	require.Equal(t, uint32(1), accountsBIP84.Accounts[0].AccountNumber)

	// Mock expectations for ListAccountsByName (BIP49 name).
	deps.addrStore.On("ActiveScopedKeyManagers").
		Return([]waddrmgr.AccountStore{deps.accountManager}).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, accBIP49Name).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   accBIP49Name,
		}, nil).Once()

	// Now, we'll do the same for the BIP0049 scope.
	accountsBIP49, err := w.ListAccountsByName(t.Context(), accBIP49Name)
	require.NoError(t, err)

	// We should have one account.
	require.Len(t, accountsBIP49.Accounts, 1)

	// The first account should be the new account.
	require.Equal(t, accBIP49Name, accountsBIP49.Accounts[0].AccountName)
	require.Equal(t, uint32(1), accountsBIP49.Accounts[0].AccountNumber)

	// Mock expectations for non-existent account.
	deps.addrStore.On("ActiveScopedKeyManagers").
		Return([]waddrmgr.AccountStore{deps.accountManager}).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, "non-existent").
		Return(uint32(0), waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrAccountNotFound,
		}).Once()

	// We should get an empty result if we query for a non-existent
	// account.
	accounts, err := w.ListAccountsByName(t.Context(), "non-existent")
	require.NoError(t, err)
	require.Empty(t, accounts.Accounts)
}

// TestGetAccount tests that the GetAccount method works as expected.
func TestGetAccount(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// We'll create a new account under the BIP0084 scope.
	scope := waddrmgr.KeyScopeBIP0084
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("CanAddAccount").Return(nil).Once()
	deps.accountManager.On("NewAccount", mock.Anything, testAccountName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   testAccountName,
		}, nil).Once()

	_, err := w.NewAccount(t.Context(), scope, testAccountName)
	require.NoError(t, err)

	// Mock expectations for GetAccount (success).
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, testAccountName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   testAccountName,
		}, nil).Once()

	// We should be able to get the new account.
	account, err := w.GetAccount(t.Context(), scope, testAccountName)
	require.NoError(t, err)
	require.Equal(t, testAccountName, account.AccountName)
	require.Equal(t, uint32(1), account.AccountNumber)
	require.Equal(t, btcutil.Amount(0), account.TotalBalance)

	// Mock expectations for GetAccount (default account).
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, "default").
		Return(uint32(0), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(0)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 0,
			AccountName:   "default",
		}, nil).Once()

	// We should also be able to get the default account.
	account, err = w.GetAccount(t.Context(), scope, "default")
	require.NoError(t, err)
	require.Equal(t, "default", account.AccountName)
	require.Equal(t, uint32(0), account.AccountNumber)
	require.Equal(t, btcutil.Amount(0), account.TotalBalance)

	// Mock expectations for GetAccount (error path).
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, "non-existent").
		Return(uint32(0), waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrAccountNotFound,
		}).Once()

	// We should get an error when trying to get a non-existent account.
	_, err = w.GetAccount(t.Context(), scope, "non-existent")
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		"expected ErrAccountNotFound",
	)
}

// TestRenameAccount tests that the RenameAccount method works as expected.
func TestRenameAccount(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// We'll create a new account under the BIP0084 scope.
	scope := waddrmgr.KeyScopeBIP0084
	oldName := "old name"
	newName := "new name"

	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("CanAddAccount").Return(nil).Once()
	deps.accountManager.On("NewAccount", mock.Anything, oldName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   oldName,
		}, nil).Once()

	_, err := w.NewAccount(t.Context(), scope, oldName)
	require.NoError(t, err)

	// Mock expectations for RenameAccount.
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, oldName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("RenameAccount", mock.Anything, uint32(1), newName).
		Return(nil).Once()

	// We should be able to rename the account.
	err = w.RenameAccount(t.Context(), scope, oldName, newName)
	require.NoError(t, err)

	// Mock expectations for GetAccount (new name).
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, newName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   newName,
		}, nil).Once()

	// We should be able to get the account by its new name.
	account, err := w.GetAccount(t.Context(), scope, newName)
	require.NoError(t, err)
	require.Equal(t, newName, account.AccountName)

	// Mock expectations for GetAccount (old name - fail).
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, oldName).
		Return(uint32(0), waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrAccountNotFound,
		}).Once()

	// We should not be able to get the account by its old name.
	_, err = w.GetAccount(t.Context(), scope, oldName)
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		"expected ErrAccountNotFound",
	)

	// Mock expectations for RenameAccount (duplicate name).
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("LookupAccount", mock.Anything, newName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On(
		"RenameAccount", mock.Anything, uint32(1), "default",
	).Return(waddrmgr.ManagerError{
		ErrorCode: waddrmgr.ErrDuplicateAccount,
	}).Once()

	// We should not be able to rename an account to an existing name.
	err = w.RenameAccount(t.Context(), scope, newName, "default")
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrDuplicateAccount),
		"expected ErrDuplicateAccount",
	)

	// Mock expectations for RenameAccount (non-existent account).
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, "non-existent").
		Return(uint32(0), waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrAccountNotFound,
		}).Once()

	// We should not be able to rename a non-existent account.
	err = w.RenameAccount(t.Context(), scope, "non-existent", "new name 2")
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		"expected ErrAccountNotFound",
	)
}

// TestBalance tests that the Balance method works as expected.
func TestBalance(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// We'll create a new account under the BIP0084 scope.
	scope := waddrmgr.KeyScopeBIP0084

	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).
		Once()

	deps.accountManager.On("CanAddAccount").Return(nil).Once()
	deps.accountManager.On("NewAccount", mock.Anything, testAccountName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   testAccountName,
		}, nil).Once()

	_, err := w.NewAccount(t.Context(), scope, testAccountName)
	require.NoError(t, err)

	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID: 0,
		Scope:    db.KeyScope(scope),
		Name:     ptr(testAccountName),
	}).Return(&db.AccountInfo{AccountNumber: 1}, nil).Once()
	deps.store.On("Balance", mock.Anything, db.BalanceParams{
		WalletID: 0,
		Account:  ptr(uint32(1)),
		MinConfs: ptr(int32(1)),
	}).Return(db.BalanceResult{}, nil).Once()

	// The balance should be zero initially.
	balance, err := w.Balance(t.Context(), 1, scope, testAccountName)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(0), balance)

	// Now, we'll add a UTXO to the account.
	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID: 0,
		Scope:    db.KeyScope(scope),
		Name:     ptr(testAccountName),
	}).Return(&db.AccountInfo{AccountNumber: 1}, nil).Once()
	deps.store.On("Balance", mock.Anything, db.BalanceParams{
		WalletID: 0,
		Account:  ptr(uint32(1)),
		MinConfs: ptr(int32(1)),
	}).Return(db.BalanceResult{Total: 100}, nil).Once()

	// The balance should now be 100.
	balance, err = w.Balance(t.Context(), 1, scope, testAccountName)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(100), balance)

	// Mock expectations for balance of non-existent account.
	deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID: 0,
		Scope:    db.KeyScope(scope),
		Name:     ptr("non-existent"),
	}).Return((*db.AccountInfo)(nil), db.ErrAccountNotFound).Once()

	// We should get an error when trying to get the balance of a
	// non-existent account.
	_, err = w.Balance(t.Context(), 1, scope, "non-existent")
	require.ErrorIs(t, err, db.ErrAccountNotFound)
}

// TestImportAccount tests that the ImportAccount works as expected.
func TestImportAccount(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, deps := createStartedWalletWithMocks(t)

	// We'll start by creating a new account under the BIP0084 scope.
	scope := waddrmgr.KeyScopeBIP0084
	addrType := waddrmgr.WitnessPubKey
	masterPriv := "tprv8ZgxMBicQKsPeWwrFuNjEGTTDSY4mRLwd2KDJAPGa1AY" +
		"quw38bZqNMSuB3V1Va3hqJBo9Pt8Sx7kBQer5cNMrb8SYquoWPt9" +
		"Y3BZdhdtUcw"
	root, err := hdkeychain.NewKeyFromString(masterPriv)
	require.NoError(t, err)
	acctPubKey := deriveAcctPubKey(t, root, scope, hardenedKey(0))

	// Mock expectations for ImportAccount.
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("NewAccountWatchingOnly", mock.Anything,
		testAccountName, acctPubKey, root.ParentFingerprint(),
		mock.Anything).Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   testAccountName,
		}, nil).Once()

	// We should be able to import the account.
	props, err := w.ImportAccount(
		t.Context(), testAccountName, acctPubKey,
		root.ParentFingerprint(), addrType, false,
	)
	require.NoError(t, err)
	require.Equal(t, testAccountName, props.AccountName)

	// Mock expectations for GetAccount.
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("LookupAccount", mock.Anything, testAccountName).
		Return(uint32(1), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(1)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 1,
			AccountName:   testAccountName,
		}, nil).Once()

	// We should be able to get the account by its name.
	_, err = w.GetAccount(t.Context(), scope, testAccountName)
	require.NoError(t, err)

	// Mock expectations for duplicate ImportAccount.
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("NewAccountWatchingOnly", mock.Anything,
		testAccountName, acctPubKey, root.ParentFingerprint(),
		mock.Anything).Return(uint32(0), waddrmgr.ManagerError{
		ErrorCode: waddrmgr.ErrDuplicateAccount,
	}).Once()

	// We should not be able to import an account with the same name.
	_, err = w.ImportAccount(
		t.Context(), testAccountName, acctPubKey,
		root.ParentFingerprint(), addrType, false,
	)
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrDuplicateAccount),
		"expected ErrDuplicateAccount",
	)

	// Mock expectations for dry-run.
	dryRunName := "dry run"

	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()

	deps.accountManager.On("NewAccountWatchingOnly", mock.Anything,
		dryRunName, acctPubKey, root.ParentFingerprint(),
		mock.Anything).Return(uint32(2), nil).Once()
	deps.accountManager.On("AccountProperties", mock.Anything, uint32(2)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 2,
			AccountName:   dryRunName,
		}, nil).Twice()
	deps.accountManager.On("InvalidateAccountCache", uint32(2)).Return().Once()
	deps.accountManager.On("NextExternalAddresses", mock.Anything, uint32(2),
		uint32(1)).Return([]waddrmgr.ManagedAddress(nil), nil).Once()
	deps.accountManager.On("NextInternalAddresses", mock.Anything, uint32(2),
		uint32(1)).Return([]waddrmgr.ManagedAddress(nil), nil).Once()

	// We should be able to do a dry run of the import.
	_, err = w.ImportAccount(
		t.Context(), dryRunName, acctPubKey,
		root.ParentFingerprint(), addrType, true,
	)
	require.NoError(t, err)

	// Mock expectations for GetAccount (fail).
	deps.addrStore.On("FetchScopedKeyManager", scope).
		Return(deps.accountManager, nil).Once()
	deps.accountManager.On("LookupAccount", mock.Anything, dryRunName).
		Return(uint32(0), waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrAccountNotFound,
		}).Once()

	// The account should not have been imported.
	_, err = w.GetAccount(t.Context(), scope, dryRunName)
	require.Error(t, err)
	require.True(
		t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		"expected ErrAccountNotFound",
	)
}
