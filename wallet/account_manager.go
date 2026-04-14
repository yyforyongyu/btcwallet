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
	"github.com/btcsuite/btcwallet/walletdb"
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

// extractAddrFromPKScript extracts an address from a public key script. If the
// script cannot be parsed or does not contain any addresses, it returns nil.
//
// The btcutil.Address is an interface that abstracts over different address
// types. Returning the interface is idiomatic in this context.
//
//nolint:ireturn
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

// accountFilter is an internal struct used to specify filters for account
// balance queries.
type accountFilter struct {
	scope *waddrmgr.KeyScope
}

// filterOption is a functional option type for account filtering.
type filterOption func(*accountFilter)

// withScope is a filter option to limit account queries to a specific key
// scope.
func withScope(scope waddrmgr.KeyScope) filterOption {
	return func(f *accountFilter) {
		f.scope = &scope
	}
}

// scopedBalances is a type alias for a map of key scopes to a map of account
// numbers to their total balance.
type scopedBalances map[waddrmgr.KeyScope]map[uint32]btcutil.Amount

// fetchAccountBalances creates a nested map of account balances, keyed by scope
// and account number.
//
// This function is a core component of the wallet's balance calculation
// logic. It is designed to be efficient, especially for wallets with a large
// number of addresses.
//
// Design Rationale:
// The primary performance consideration is the trade-off between iterating
// through all Unspent Transaction Outputs (UTXOs) versus iterating through all
// derived addresses for all accounts. A mature wallet may have millions of used
// addresses, but a relatively small set of UTXOs. Therefore, this function is
// optimized for this common case.
//
// The algorithm works as follows:
// 1. Make a single pass over all UTXOs in the wallet.
// 2. For each UTXO, look up the address and its corresponding account.
// 3. Aggregate the UTXO values into a map of balances per account.
//
// This approach avoids iterating through a potentially massive number of
// addresses and performing a database lookup for each one to check for a
// balance. Instead, it starts with the smaller, known set of UTXOs and works
// backward to the accounts.
//
// Filters:
// The function's behavior can be customized by passing one or more filterOption
// functions. This allows the caller to restrict the balance calculation to:
//   - A specific key scope (withScope).
//
// If no filters are provided, balances for all accounts across all scopes will
// be fetched.
//
// TODO(yy): With a future SQL backend, this entire function could be
// replaced by a single, more efficient query. By adding `account_id` and
// `key_scope` columns to the `outputs` table, we could perform a direct
// aggregation in the database, like:
// `SELECT key_scope, account_id, SUM(value) FROM outputs
// WHERE is_spent = false GROUP BY key_scope, account_id;`.
// This would be significantly faster as the database is optimized for
// these types of operations.
//
// TODO(yy): The current UTXO-first approach is optimal for mature wallets where
// the number of addresses greatly exceeds the number of UTXOs. For new wallets
// or accounts, an address-first approach might be more efficient. A future
// improvement could be to dynamically choose the strategy based on the relative
// counts of addresses and UTXOs for the accounts in question.
func (w *Wallet) fetchAccountBalances(tx walletdb.ReadTx,
	opts ...filterOption) (scopedBalances, error) {

	// Apply the filter options.
	filter := &accountFilter{}
	for _, opt := range opts {
		opt(filter)
	}

	addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
	txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

	// First, fetch all unspent outputs.
	utxos, err := w.txStore.UnspentOutputs(txmgrNs)
	if err != nil {
		return nil, err
	}

	// Now, create the nested map to hold the balances.
	scopedBalances := make(scopedBalances)

	// Iterate through all UTXOs, mapping them back to their owning account
	// to aggregate the total balance for each.
	for _, utxo := range utxos {
		addr := extractAddrFromPKScript(
			utxo.PkScript, w.cfg.ChainParams,
		)
		if addr == nil {
			// This can happen for non-standard script types.
			continue
		}

		// Now that we have the address, we'll look up which account it
		// belongs to.
		scope, accNum, err := w.addrStore.AddrAccount(addrmgrNs, addr)
		if err != nil {
			log.Errorf("Unable to query account using address %v: "+
				"%v", addr, err)

			continue
		}

		// If a scope filter was provided, apply it now.
		if filter.scope != nil {
			if scope.Scope() != *filter.scope {
				continue
			}
		}

		// We'll use a nested map to store balances. If this is the
		// first time we've seen this key scope, we'll need to
		// initialize the inner map.
		keyScope := scope.Scope()
		if _, ok := scopedBalances[keyScope]; !ok {
			scopedBalances[keyScope] = make(
				map[uint32]btcutil.Amount,
			)
		}

		// Finally, we'll add the UTXO's value to the account's
		// balance.
		scopedBalances[keyScope][accNum] += utxo.Amount
	}

	return scopedBalances, nil
}

// listAccountsWithBalances is a helper function that iterates through all
// accounts in a given scope, fetches their properties, and combines them with
// the provided account balances.
//
// This function is designed to be called after the balances for all relevant
// accounts have already been computed by a function like fetchAccountBalances.
// It serves as the final step to assemble the complete AccountResult objects.
//
// The function operates as follows:
//  1. It determines the last account number for the given scope.
//  2. It iterates from account number 0 to the last account.
//  3. For each account, it retrieves its properties from the database.
//  4. It looks up the pre-calculated balance from the accountBalances map.
//  5. It constructs an AccountResult object with both the properties and the
//     balance.
//
// This separation of concerns (first calculating all balances, then assembling
// the results) is a key part of the overall optimization strategy. It ensures
// that we can efficiently gather all necessary data in distinct phases, rather
// than mixing database reads and balance calculations in a less efficient
// manner.
func listAccountsWithBalances(scopeMgr waddrmgr.AccountStore,
	addrmgrNs walletdb.ReadBucket,
	accountBalances map[uint32]btcutil.Amount) ([]AccountResult, error) {

	var accounts []AccountResult

	lastAccount, err := scopeMgr.LastAccount(addrmgrNs)
	if err != nil {
		// If the scope has no accounts, we can just return an empty
		// slice. This is a normal condition and not an error.
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return nil, nil
		}

		return nil, err
	}

	// Iterate through all accounts from 0 to the last known account
	// number for this scope.
	for accNum := uint32(0); accNum <= lastAccount; accNum++ {
		// For each account number, we'll fetch its full set of
		// properties from the database.
		props, err := scopeMgr.AccountProperties(addrmgrNs, accNum)
		if err != nil {
			return nil, err
		}

		// We'll look up the pre-calculated balance for this account.
		// If the account has no UTXOs, it won't be in the map, so
		// we'll default to a balance of 0.
		balance, ok := accountBalances[accNum]
		if !ok {
			balance = 0
		}

		// Finally, we'll construct the full account result and add it
		// to our list.
		accounts = append(accounts, AccountResult{
			AccountProperties: *props,
			TotalBalance:      balance,
		})
	}

	return accounts, nil
}
