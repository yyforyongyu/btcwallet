// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// AccountManager provides a high-level interface for managing wallet
// accounts.
//
// # Account Derivation
//
// The wallet uses a hierarchical deterministic (HD) key generation scheme based
// on BIP-44. Addresses are derived from a path with the following structure:
//
//	m / purpose' / coin_type' / account' / change / address_index
//
// The AccountManager abstracts this complexity by mapping a human-readable
// name to the cryptographic `account'` index within a given KeyScope.
//
// # Key Scopes
//
// The `purpose'` and `coin_type'` fields of the derivation path are defined by
// a waddrmgr.KeyScope. This allows the wallet to manage different kinds of
// accounts (and address types) simultaneously. The wallet initializes a set of
// default scopes upon creation:
//   - KeyScopeBIP0044: For legacy P2PKH addresses.
//   - KeyScopeBIP0049Plus: For P2WPKH addresses nested in P2SH (NP2WKH).
//   - KeyScopeBIP0084: For native SegWit v0 P2WPKH addresses.
//   - KeyScopeBIP0086: For native Taproot v1 P2TR addresses.
//
// # Account Names and Reserved Accounts
//
// An account name is a human-readable identifier that is unique *within its
// KeyScope*. The wallet initializes two special, reserved accounts:
//   - "default": The first user-created account (account number 0). This
//     account is created for each of the default key scopes and CAN be renamed.
//   - "imported": A special account that holds all individually imported keys.
//     This account is global and CANNOT be renamed.
type AccountManager interface {
	// NewAccount creates a new account for a given key scope and name. The
	// provided name must be unique within that key scope.
	NewAccount(ctx context.Context, scope db.KeyScope, name string) (
		*db.AccountInfo, error)

	// ListAccounts returns a list of all accounts managed by the wallet.
	ListAccounts(ctx context.Context) (*AccountsResult, error)

	// ListAccountsByScope returns a list of all accounts for a given key
	// scope.
	ListAccountsByScope(ctx context.Context, scope db.KeyScope) (
		*AccountsResult, error)

	// ListAccountsByName searches for accounts with the given name across
	// all key scopes. Because names are not globally unique, this may
	// return multiple results.
	ListAccountsByName(ctx context.Context, name string) (
		*AccountsResult, error)

	// GetAccount returns the properties for a specific account, looked up
	// by its key scope and unique name within that scope.
	GetAccount(ctx context.Context, scope db.KeyScope, name string) (
		*db.AccountInfo, error)

	// RenameAccount renames an existing account. To uniquely identify the
	// account, the key scope must be provided. The new name must be unique
	// within that same key scope. The reserved "imported" account cannot
	// be renamed.
	RenameAccount(ctx context.Context, scope db.KeyScope,
		oldName string, newName string) error

	// Balance returns the balance for a specific account, identified by its
	// scope and name, for a given number of required confirmations.
	Balance(ctx context.Context, conf int32, scope db.KeyScope,
		name string) (btcutil.Amount, error)

	// ImportAccount imports an account from an extended public or private
	// key. The key scope is derived from the version bytes of the
	// extended key. The account name must be unique within the derived
	// scope. If dryRun is true, the import is validated but not persisted.
	ImportAccount(ctx context.Context, name string,
		accountKey *hdkeychain.ExtendedKey,
		masterKeyFingerprint uint32, addrType db.AddressType,
		dryRun bool) (*db.AccountInfo, error)
}

// A compile time check to ensure that Wallet implements the interface.
var _ AccountManager = (*Wallet)(nil)

// NewAccount creates the next account and returns its account number. The name
// must be unique under the kep scope. In order to support automatic seed
// restoring, new accounts may not be created when all of the previous 100
// accounts have no transaction history (this is a deviation from the BIP0044
// spec, which allows no unused account gaps).
func (w *Wallet) NewAccount(ctx context.Context, scope db.KeyScope,
	name string) (*db.AccountInfo, error) {

	// TODO(yy): check if we can add a new account.

	params := db.CreateAccountParams{
		WalletID: w.ID(),
		Scope:    scope,
		Name:     name,
	}
	info, err := w.store.CreateAccount(ctx, params)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

// AccountResult is the result of a ListAccounts query.
type AccountResult struct {
	// AccountProperties is the account's properties.
	db.AccountInfo

	// TotalBalance is the total balance of the account.
	TotalBalance btcutil.Amount
}

// AccountsResult is the result of a ListAccounts query. It contains a list of
// accounts and the current block height and hash.
type AccountsResult struct {
	// Accounts is a list of accounts.
	Accounts []db.AccountInfo

	// CurrentBlockHash is the hash of the current block.
	CurrentBlockHash chainhash.Hash

	// CurrentBlockHeight is the height of the current block.
	CurrentBlockHeight int32
}

// ListAccounts returns a list of all accounts for the wallet, including those
// with a zero balance. The current chain tip is included in the result for
// reference.
func (w *Wallet) ListAccounts(ctx context.Context) (*AccountsResult, error) {
	query := db.ListAccountsQuery{
		WalletID: w.ID(),
	}
	accounts, err := w.store.ListAccounts(ctx, query)
	if err != nil {
		return nil, err
	}

	// Include the wallet's current sync state in the result to provide a
	// point-in-time reference for the balances.
	walletInfo, err := w.store.GetWallet(ctx, w.Name())
	if err != nil {
		return nil, err
	}
	syncBlock := walletInfo.SyncState
	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   syncBlock.SyncedTo,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
}

// ListAccountsByScope returns a list of all accounts for a given key scope,
// including those with a zero balance. The current chain tip is included for
// reference.
func (w *Wallet) ListAccountsByScope(ctx context.Context,
	scope db.KeyScope) (*AccountsResult, error) {

	query := db.ListAccountsQuery{
		WalletID: w.ID(),
		Scope:    &scope,
	}
	accounts, err := w.store.ListAccounts(ctx, query)
	if err != nil {
		return nil, err
	}

	// Include the wallet's current sync state in the result.
	walletInfo, err := w.store.GetWallet(ctx, w.Name())
	if err != nil {
		return nil, err
	}
	syncBlock := walletInfo.SyncState
	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   syncBlock.SyncedTo,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
}

// ListAccountsByName returns a list of all accounts that have a given name.
// Since account names are only unique within a key scope, this can return
// multiple accounts. The current chain tip is included for reference.
func (w *Wallet) ListAccountsByName(ctx context.Context,
	name string) (*AccountsResult, error) {

	query := db.ListAccountsQuery{
		WalletID: w.ID(),
		Name:     &name,
	}
	accounts, err := w.store.ListAccounts(ctx, query)
	if err != nil {
		return nil, err
	}

	syncBlock, err := w.store.GetWallet(ctx, w.Name())
	if err != nil {
		return nil, err
	}
	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   syncBlock.SyncState.SyncedTo,
		CurrentBlockHeight: syncBlock.SyncState.Height,
	}, nil
}

func (w *Wallet) GetAccount(ctx context.Context, scope db.KeyScope,
	name string) (*db.AccountInfo, error) {

	query := db.GetAccountQuery{
		WalletID: w.ID(),
		Scope:    scope,
		Name:     &name,
	}
	info, err := w.store.GetAccount(ctx, query)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

// RenameAccount renames an existing account. The new name must be unique within
// the same key scope. The reserved "imported" account cannot be renamed.
func (w *Wallet) RenameAccount(ctx context.Context, scope db.KeyScope,
	oldName, newName string) error {

	// Validate the new account name to ensure it meets the required
	// criteria.
	if err := waddrmgr.ValidateAccountName(newName); err != nil {
		return err
	}

	params := db.UpdateAccountNameParams{
		WalletID: w.ID(),
		Scope:    scope,
		OldName:  oldName,
		NewName:  newName,
	}
	return w.store.UpdateAccountName(ctx, params)
}

// Balance returns the balance for a specific account, identified by its scope
// and name, for a given number of required confirmations.
func (w *Wallet) Balance(ctx context.Context, conf int32,
	scope db.KeyScope, name string) (btcutil.Amount, error) {

	query := db.GetAccountQuery{
		WalletID: w.ID(),
		Scope:    scope,
		Name:     &name,
	}
	info, err := w.store.GetAccount(ctx, query)
	if err != nil {
		return 0, err
	}

	// TODO(yy): filter by confs
	_ = conf

	return info.ConfirmedBalance + info.UnconfirmedBalance, nil
}

// ImportAccount imports an account from an extended public or private key.
func (w *Wallet) ImportAccount(ctx context.Context,
	name string, accountKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrType db.AddressType,
	dryRun bool) (*db.AccountInfo, error) {

	// TODO(yy): implement dry run.
	_ = dryRun

	params := db.ImportAccountParams{
		WalletID:             w.ID(),
		Name:                 name,
		AccountKey:           accountKey,
		MasterKeyFingerprint: masterKeyFingerprint,
		AddressType:          addrType,
	}
	info, err := w.store.ImportAccount(ctx, params)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

// extractAddrFromPKScript extracts an address from a public key script. If the
// script cannot be parsed or does not contain any addresses, it returns nil.
func extractAddrFromPKScript(pkScript []byte,
	chainParams *chaincfg.Params) btcutil.Address {

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		pkScript, chainParams,
	)
	if err != nil {
		// We'll log the error and return nil to prevent a single
		// un-parsable script from failing a larger operation.
		log.Errorf("Unable to parse pkscript: %v", err)
		return nil
	}

	// This can happen for scripts that don't resolve to a standard address,
	// such as OP_RETURN outputs. We can safely ignore these.
	if len(addrs) == 0 {
		return nil
	}

	// TODO(yy): For bare multisig outputs, ExtractPkScriptAddrs can
	// return more than one address. Currently, we are only considering
	// the first address, which could lead to incorrect balance
	// attribution. However, since bare multisig is rare and modern
	// wallets almost exclusively use P2SH or P2WSH for multisig (which
	// are correctly handled as a single address), this is a low-priority
	// issue.
	return addrs[0]
}
