// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet implements the account management for the wallet.
//
// TODO(yy): bring wrapcheck back when implementing the `Store` interface.
//
//nolint:wrapcheck
package wallet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/netparams"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
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
	NewAccount(ctx context.Context, scope waddrmgr.KeyScope, name string) (
		*waddrmgr.AccountProperties, error)

	// ListAccounts returns a list of all accounts managed by the wallet.
	ListAccounts(ctx context.Context) (*AccountsResult, error)

	// ListAccountsByScope returns a list of all accounts for a given key
	// scope.
	ListAccountsByScope(ctx context.Context, scope waddrmgr.KeyScope) (
		*AccountsResult, error)

	// ListAccountsByName searches for accounts with the given name across
	// all key scopes. Because names are not globally unique, this may
	// return multiple results.
	ListAccountsByName(ctx context.Context, name string) (
		*AccountsResult, error)

	// GetAccount returns the properties for a specific account, looked up
	// by its key scope and unique name within that scope.
	GetAccount(ctx context.Context, scope waddrmgr.KeyScope, name string) (
		*AccountResult, error)

	// RenameAccount renames an existing account. To uniquely identify the
	// account, the key scope must be provided. The new name must be unique
	// within that same key scope. The reserved "imported" account cannot
	// be renamed.
	RenameAccount(ctx context.Context, scope waddrmgr.KeyScope,
		oldName string, newName string) error

	// Balance returns the balance for a specific account, identified by its
	// scope and name, for a given number of required confirmations.
	Balance(ctx context.Context, conf uint32, scope waddrmgr.KeyScope,
		name string) (btcutil.Amount, error)

	// ImportAccount imports an account from an extended public or private
	// key. The key scope is derived from the version bytes of the
	// extended key. The account name must be unique within the derived
	// scope. If dryRun is true, the import is validated but not persisted.
	ImportAccount(ctx context.Context, name string,
		accountKey *hdkeychain.ExtendedKey,
		masterKeyFingerprint uint32, addrType waddrmgr.AddressType,
		dryRun bool) (*waddrmgr.AccountProperties, error)
}

var errConfirmationCountOverflow = errors.New(
	"confirmation count exceeds int32",
)

// A compile time check to ensure that Wallet implements the interface.
var _ AccountManager = (*Wallet)(nil)

// NewAccount creates the next account and returns its account number. The name
// must be unique under the kep scope. In order to support automatic seed
// restoring, new accounts may not be created when all of the previous 100
// accounts have no transaction history (this is a deviation from the BIP0044
// spec, which allows no unused account gaps).
func (w *Wallet) NewAccount(ctx context.Context, scope waddrmgr.KeyScope,
	name string) (*waddrmgr.AccountProperties, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	info, err := w.store.CreateDerivedAccount(
		ctx, db.CreateDerivedAccountParams{
			WalletID: w.id,
			Scope:    db.KeyScope(scope),
			Name:     name,
		},
	)
	if err != nil {
		return nil, err
	}

	props := accountPropertiesFromStoreInfo(*info)

	return &props, nil
}

// AccountResult is the result of a ListAccounts query.
type AccountResult struct {
	// AccountProperties is the account's properties.
	waddrmgr.AccountProperties

	// TotalBalance is the total balance of the account.
	TotalBalance btcutil.Amount
}

// AccountsResult is the result of a ListAccounts query. It contains a list of
// accounts and the current block height and hash.
type AccountsResult struct {
	// Accounts is a list of accounts.
	Accounts []AccountResult

	// CurrentBlockHash is the hash of the current block.
	CurrentBlockHash chainhash.Hash

	// CurrentBlockHeight is the height of the current block.
	CurrentBlockHeight int32
}

// accountResultFromStoreInfo adapts one store account row to the wallet-facing
// account result.
func accountResultFromStoreInfo(info db.AccountInfo) AccountResult {
	return AccountResult{
		AccountProperties: accountPropertiesFromStoreInfo(info),
		TotalBalance:      info.ConfirmedBalance + info.UnconfirmedBalance,
	}
}

// accountPropertiesFromStoreInfo adapts one store account row to legacy wallet
// account properties.
func accountPropertiesFromStoreInfo(
	info db.AccountInfo,
) waddrmgr.AccountProperties {

	return waddrmgr.AccountProperties{
		AccountNumber:    info.AccountNumber,
		AccountName:      info.AccountName,
		ExternalKeyCount: info.ExternalKeyCount,
		InternalKeyCount: info.InternalKeyCount,
		ImportedKeyCount: info.ImportedKeyCount,
		KeyScope:         waddrmgr.KeyScope(info.KeyScope),
		IsWatchOnly:      info.IsWatchOnly,
	}
}

// accountPropertiesFromStoreProps adapts one store account-properties record to
// the wallet-facing account properties type.
func accountPropertiesFromStoreProps(
	props db.AccountProperties,
) waddrmgr.AccountProperties {

	result := waddrmgr.AccountProperties{
		AccountNumber:        props.AccountNumber,
		AccountName:          props.AccountName,
		ExternalKeyCount:     props.ExternalKeyCount,
		InternalKeyCount:     props.InternalKeyCount,
		ImportedKeyCount:     props.ImportedKeyCount,
		MasterKeyFingerprint: props.MasterKeyFingerprint,
		KeyScope:             waddrmgr.KeyScope(props.KeyScope),
		IsWatchOnly:          props.IsWatchOnly,
	}

	if props.AddrSchema != nil {
		result.AddrSchema = &waddrmgr.ScopeAddrSchema{
			InternalAddrType: waddrmgr.AddressType(
				props.AddrSchema.InternalAddrType,
			),
			ExternalAddrType: waddrmgr.AddressType(
				props.AddrSchema.ExternalAddrType,
			),
		}
	}

	return result
}

// accountResultsFromStoreInfos adapts a slice of store account rows to wallet
// account results.
func accountResultsFromStoreInfos(infos []db.AccountInfo) []AccountResult {
	results := make([]AccountResult, len(infos))
	for i := range infos {
		results[i] = accountResultFromStoreInfo(infos[i])
	}

	return results
}

// ListAccounts returns a list of all accounts for the wallet, including those
// with a zero balance. The current chain tip is included in the result for
// reference.
//
// The function calculates balances by first creating a comprehensive map of
// balances for all accounts that currently own UTXOs. It then iterates through
// all known accounts across all key scopes, retrieving their properties and
// assigning the pre-calculated balance. Accounts with no UTXOs will correctly
// be assigned a zero balance.
//
// The time complexity of this method is O(U*logA + A), where U is the number of
// UTXOs and A is the number of accounts in the wallet. A potential future
// improvement is to make the balance calculation optional.
func (w *Wallet) ListAccounts(ctx context.Context) (*AccountsResult, error) {
	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	infos, err := w.store.ListAccounts(ctx, db.ListAccountsQuery{
		WalletID: w.id,
	})
	if err != nil {
		return nil, err
	}

	// Include the wallet's current sync state in the result to provide a
	// point-in-time reference for the balances.
	syncBlock := w.addrStore.SyncedTo()

	return &AccountsResult{
		Accounts:           accountResultsFromStoreInfos(infos),
		CurrentBlockHash:   syncBlock.Hash,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
}

// ListAccountsByScope returns a list of all accounts for a given key scope,
// including those with a zero balance. The current chain tip is included for
// reference.
//
// The function first fetches the balances for all accounts within the given
// scope by iterating over the wallet's UTXO set. It then retrieves the
// properties for each account in that scope and combines them with the
// pre-calculated balances.
//
// The time complexity of this method is O(U*logA + A), where U is the number of
// UTXOs and A is the number of accounts in the wallet.
func (w *Wallet) ListAccountsByScope(ctx context.Context,
	scope waddrmgr.KeyScope) (*AccountsResult, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	storeScope := db.KeyScope(scope)

	infos, err := w.store.ListAccounts(ctx, db.ListAccountsQuery{
		WalletID: w.id,
		Scope:    &storeScope,
	})
	if err != nil {
		return nil, err
	}

	// Include the wallet's current sync state in the result.
	syncBlock := w.addrStore.SyncedTo()

	return &AccountsResult{
		Accounts:           accountResultsFromStoreInfos(infos),
		CurrentBlockHash:   syncBlock.Hash,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
}

// ListAccountsByName returns a list of all accounts that have a given name.
// Since account names are only unique within a key scope, this can return
// multiple accounts. The current chain tip is included for reference.
//
// The function first calculates the balances for any accounts matching the
// given name, and then iterates through all key scopes to find and retrieve
// the properties of those accounts.
//
// The time complexity of this method is O(U*logA), where U is the number of
// UTXOs and logA is the cost of an account lookup.
func (w *Wallet) ListAccountsByName(ctx context.Context,
	name string) (*AccountsResult, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	infos, err := w.store.ListAccounts(ctx, db.ListAccountsQuery{
		WalletID: w.id,
		Name:     &name,
	})
	if err != nil {
		return nil, err
	}

	syncBlock := w.addrStore.SyncedTo()

	return &AccountsResult{
		Accounts:           accountResultsFromStoreInfos(infos),
		CurrentBlockHash:   syncBlock.Hash,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
}

// GetAccount returns the account for a given account name and key scope.
//
// The function first looks up the account's properties and then calculates its
// balance by iterating over the wallet's UTXO set.
//
// The time complexity of this method is O(U*logA), where U is the number of
// UTXOs and logA is the cost of an account lookup.
func (w *Wallet) GetAccount(ctx context.Context, scope waddrmgr.KeyScope,
	name string) (*AccountResult, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	info, err := w.store.GetAccount(ctx, db.GetAccountQuery{
		WalletID: w.id,
		Scope:    db.KeyScope(scope),
		Name:     &name,
	})
	if err != nil {
		return nil, err
	}

	result := accountResultFromStoreInfo(*info)

	return &result, nil
}

// RenameAccount renames an existing account. The new name must be unique within
// the same key scope. The reserved "imported" account cannot be renamed.
//
// The time complexity of this method is dominated by the database lookup for
// the old account name.
func (w *Wallet) RenameAccount(ctx context.Context, scope waddrmgr.KeyScope,
	oldName, newName string) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	return w.store.RenameAccount(ctx, db.RenameAccountParams{
		WalletID: w.id,
		Scope:    db.KeyScope(scope),
		OldName:  oldName,
		NewName:  newName,
	})
}

// Balance returns the balance for a specific account, identified by its scope
// and name, for a given number of required confirmations.
//
// The function first looks up the account number and then iterates through all
// unspent transaction outputs (UTXOs), summing the values of those that belong
// to the account and meet the required number of confirmations.
//
// The time complexity of this method is O(U*logA), where U is the number of
// UTXOs and logA is the cost of an account lookup.
func (w *Wallet) Balance(ctx context.Context, conf uint32,
	scope waddrmgr.KeyScope, name string) (btcutil.Amount, error) {

	err := w.state.validateStarted()
	if err != nil {
		return 0, err
	}

	account, err := w.store.GetAccount(ctx, db.GetAccountQuery{
		WalletID: w.id,
		Scope:    db.KeyScope(scope),
		Name:     &name,
	})
	if err != nil {
		return 0, err
	}

	if conf > math.MaxInt32 {
		return 0, fmt.Errorf("%w: %d", errConfirmationCountOverflow, conf)
	}

	minConfs := int32(conf)
	accountNum := account.AccountNumber

	balance, err := w.store.Balance(ctx, db.BalanceParams{
		WalletID: w.id,
		Account:  &accountNum,
		MinConfs: &minConfs,
	})
	if err != nil {
		return 0, err
	}

	return balance.Total, nil
}

// ImportAccount imports an account from an extended public or private key. The
// key scope is derived from the version bytes of the extended key. The account
// name must be unique within the derived scope. If dryRun is true, the import
// is validated but not persisted.
//
// The time complexity of this method is dominated by the database lookup to
// ensure the account name is unique within the scope.
func (w *Wallet) ImportAccount(ctx context.Context,
	name string, accountKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrType waddrmgr.AddressType,
	dryRun bool) (*waddrmgr.AccountProperties, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	return w.importAccountInternal(
		ctx, name, accountKey, masterKeyFingerprint, addrType, dryRun,
	)
}

// importAccountInternal is the internal implementation of ImportAccount,
// allowing callers (like Manager.Create) to bypass the started check.
func (w *Wallet) importAccountInternal(ctx context.Context,
	name string, accountKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrType waddrmgr.AddressType,
	dryRun bool) (*waddrmgr.AccountProperties, error) {

	// Ensure we have a valid account public key. We require an account-level
	// key (depth 3) to properly manage the derivation path.
	err := validateExtendedPubKey(accountKey, true, w.cfg.ChainParams)
	if err != nil {
		return nil, err
	}

	// Determine what key scope the account public key should belong to and
	// whether it should use a custom address schema. This is inferred from
	// the key's HD version bytes.
	keyScope, addrSchema, err := keyScopeFromPubKey(accountKey, &addrType)
	if err != nil {
		return nil, err
	}

	var storeAddrSchema *db.ScopeAddrSchema
	if addrSchema != nil {
		storeAddrSchema = &db.ScopeAddrSchema{
			InternalAddrType: db.AddressType(addrSchema.InternalAddrType),
			ExternalAddrType: db.AddressType(addrSchema.ExternalAddrType),
		}
	}

	props, err := w.store.ImportAccount(ctx, db.ImportAccountParams{
		WalletID:          w.id,
		Name:              name,
		Scope:             db.KeyScope(keyScope),
		AccountKey:        accountKey,
		MasterFingerprint: masterKeyFingerprint,
		AddrSchema:        storeAddrSchema,
		DryRun:            dryRun,
	})
	if err != nil {
		return nil, err
	}

	waddrProps := accountPropertiesFromStoreProps(*props)

	return &waddrProps, nil
}

// validateExtendedPubKey ensures a sane derived public key is provided.
func validateExtendedPubKey(pubKey *hdkeychain.ExtendedKey,
	isAccountKey bool, chainParams *chaincfg.Params) error {

	// Private keys are not allowed.
	if pubKey.IsPrivate() {
		return fmt.Errorf("%w: private keys cannot be imported",
			ErrInvalidAccountKey)
	}

	// The public key must have a version corresponding to the current
	// chain.
	if !isPubKeyForNet(pubKey, chainParams) {
		return fmt.Errorf("%w: expected extended public key for current "+
			"network %v", ErrInvalidAccountKey, chainParams.Name)
	}

	// Verify the extended public key's depth and child index based on
	// whether it's an account key or not.
	if isAccountKey {
		if pubKey.Depth() != accountPubKeyDepth {
			return fmt.Errorf("%w: must be of the form "+
				"m/purpose'/coin_type'/account'", ErrInvalidAccountKey)
		}

		if pubKey.ChildIndex() < hdkeychain.HardenedKeyStart {
			return fmt.Errorf("%w: must be hardened", ErrInvalidAccountKey)
		}

		return nil
	}

	if pubKey.Depth() != pubKeyDepth {
		return fmt.Errorf("%w: must be of the form "+
			"m/purpose'/coin_type'/account'/change/address_index",
			ErrInvalidAccountKey)
	}

	if pubKey.ChildIndex() >= hdkeychain.HardenedKeyStart {
		return fmt.Errorf("%w: must not be hardened", ErrInvalidAccountKey)
	}

	return nil
}

// isPubKeyForNet determines if the given public key is for the current network
// the wallet is operating under.
//
// Ignore exhaustive linter as the `wire.SigNet` is covered by `SigNetWire`.
//
//nolint:exhaustive,cyclop
func isPubKeyForNet(pubKey *hdkeychain.ExtendedKey,
	chainParams *chaincfg.Params) bool {

	version := waddrmgr.HDVersion(binary.BigEndian.Uint32(pubKey.Version()))
	switch chainParams.Net {
	case wire.MainNet:
		return version == waddrmgr.HDVersionMainNetBIP0044 ||
			version == waddrmgr.HDVersionMainNetBIP0049 ||
			version == waddrmgr.HDVersionMainNetBIP0084

	case wire.TestNet, wire.TestNet3, wire.TestNet4,
		netparams.SigNetWire(chainParams):

		return version == waddrmgr.HDVersionTestNetBIP0044 ||
			version == waddrmgr.HDVersionTestNetBIP0049 ||
			version == waddrmgr.HDVersionTestNetBIP0084

	// For simnet, we'll also allow the mainnet versions since simnet
	// doesn't have defined versions for some of our key scopes, and the
	// mainnet versions are usually used as the default regardless of the
	// network/key scope.
	case wire.SimNet:
		return version == waddrmgr.HDVersionSimNetBIP0044 ||
			version == waddrmgr.HDVersionMainNetBIP0049 ||
			version == waddrmgr.HDVersionMainNetBIP0084

	default:
		return false
	}
}

// extractAddrFromPKScript extracts the first standard address from one script.
//
//nolint:ireturn
func extractAddrFromPKScript(pkScript []byte,
	chainParams *chaincfg.Params) btcutil.Address {

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		pkScript, chainParams,
	)
	if err != nil {
		log.Errorf("Unable to parse pkscript: %v", err)
		return nil
	}

	if len(addrs) == 0 {
		return nil
	}

	return addrs[0]
}
