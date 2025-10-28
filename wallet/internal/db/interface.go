// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// Store is the top-level interface that combines all the more granular
// sub-interfaces. This is the single entry point for all wallet database
// operations.
type Store interface {
	WalletStore
	AccountStore
	AddressStore
	TxStore
	UTXOStore
}

// WalletStore defines the methods for wallet-level operations.
type WalletStore interface {
	CreateWallet(ctx context.Context, params CreateWalletParams) (walletID uint64, err error)
	GetWallet(ctx context.Context, name string) (WalletInfo, error)
	ListWallets(ctx context.Context) ([]WalletInfo, error)
	UpdateSyncState(ctx context.Context, params UpdateSyncStateParams) error
	GetEncryptedHDSeed(ctx context.Context) ([]byte, error)
	ChangePassphrase(ctx context.Context, old, new []byte, private bool) error
	Unlock(ctx context.Context, passphrase []byte) error
	Lock(ctx context.Context)
	IsLocked(ctx context.Context) bool
	BirthdayBlock(ctx context.Context) (waddrmgr.BlockStamp, bool, error)
	SetBirthday(ctx context.Context, birthday time.Time) error
	SetBirthdayBlock(ctx context.Context, block waddrmgr.BlockStamp, verified bool) error
}

// AccountStore defines the database actions for managing accounts.
type AccountStore interface {
	CreateAccount(ctx context.Context, params CreateAccountParams) (AccountInfo, error)
	ImportAccount(ctx context.Context, params ImportAccountParams) (AccountInfo, error)
	GetAccount(ctx context.Context, query GetAccountQuery) (AccountInfo, error)
	ListAccounts(ctx context.Context, query ListAccountsQuery) ([]AccountInfo, error)
	UpdateAccountName(ctx context.Context, params UpdateAccountNameParams) error
	RenameAccount(ctx context.Context, params RenameAccountParams) error
	FetchScopedKeyManager(scope KeyScope) (waddrmgr.AccountStore, error)
	NewScopedKeyManager(scope KeyScope, addrSchema waddrmgr.ScopeAddrSchema) (waddrmgr.AccountStore, error)
}

// AddressStore defines the database actions for managing addresses.
type AddressStore interface {
	CreateAddress(ctx context.Context, params CreateAddressParams) (AddressInfo, error)
	ImportAddress(ctx context.Context, params ImportAddressData) (AddressInfo, error)
	GetAddress(ctx context.Context, query GetAddressQuery) (AddressInfo, error)
	ListAddresses(ctx context.Context, query ListAddressesQuery) ([]AddressInfo, error)
	MarkAddressAsUsed(ctx context.Context, params MarkAddressAsUsedParams) error
	GetPrivateKey(ctx context.Context, addr btcutil.Address) (*btcec.PrivateKey, bool, error)
	DeriveFromKeyPath(ctx context.Context, scope KeyScope, path waddrmgr.DerivationPath) (waddrmgr.ManagedAddress, error)
	NewAddress(ctx context.Context, accountName string, addrType AddressType, withChange bool) (btcutil.Address, error)
}

// TxStore defines the database actions for managing transaction records.
type TxStore interface {
	CreateTx(ctx context.Context, params CreateTxParams) error
	UpdateTx(ctx context.Context, params UpdateTxParams) error
	GetTx(ctx context.Context, query GetTxQuery) (TxInfo, error)
	ListTxs(ctx context.Context, query ListTxsQuery) ([]TxInfo, error)
	DeleteTx(ctx context.Context, params DeleteTxParams) error
	AddRelevantTxs(ctx context.Context, recs []*wtxmgr.TxRecord,
		block *wtxmgr.BlockMeta) error
	Balance(ctx context.Context, minConfirms int32) (btcutil.Amount, error)
	Rollback(ctx context.Context, height int32) error
}

// UTXOStore defines the database actions for managing the UTXO set.
type UTXOStore interface {
	ListUTXOs(ctx context.Context, query ListUtxosQuery) ([]UtxoInfo, error)
	LeaseOutput(ctx context.Context, id wtxmgr.LockID, op wire.OutPoint,
		duration time.Duration) (time.Time, error)
	ReleaseOutput(ctx context.Context, id wtxmgr.LockID, op wire.OutPoint) error
	ListLeasedOutputs(ctx context.Context) ([]*wtxmgr.LockedOutput, error)
}