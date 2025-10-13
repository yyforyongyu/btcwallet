// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// waddrmgrNamespaceKey is the namespace key for the address manager.
	waddrmgrNamespaceKey = []byte("waddrmgr")

	// wtxmgrNamespaceKey is the namespace key for the transaction manager.
	wtxmgrNamespaceKey = []byte("wtxmgr")

	bucketUnmined        = []byte("unmined")
	bucketUnminedCredits = []byte("unminedcredits")
)

// KvdbStore is the concrete implementation of the Store interface. It acts as an
// adapter to translate the clean API of the Store into the legacy waddrmgr and
// wtxmgr APIs.
type KvdbStore struct {
	db        walletdb.DB
	addrStore *waddrmgr.Manager
}

// NewKvdbStore creates a new database driver.
func NewKvdbStore(db walletdb.DB, addrStore *waddrmgr.Manager) *KvdbStore {

	return &KvdbStore{
		db:        db,
		addrStore: addrStore,
	}
}

// A compile-time check to ensure that KvdbStore implements the Store interface.
var _ Store = (*KvdbStore)(nil)

// ============================================================================
// WalletStore Implementation
// ============================================================================

// CreateWallet is a placeholder for the CreateWallet method.
func (d *KvdbStore) CreateWallet(ctx context.Context, params CreateWalletParams) (uint64, error) {
	// TODO(yy): implement
	return 0, nil
}

// GetWallet is a placeholder for the GetWallet method.
func (d *KvdbStore) GetWallet(ctx context.Context, name string) (WalletInfo, error) {
	// TODO(yy): implement
	return WalletInfo{}, nil
}

// ListWallets is a placeholder for the ListWallets method.
func (d *KvdbStore) ListWallets(ctx context.Context) ([]WalletInfo, error) {
	// TODO(yy): implement
	return nil, nil
}

// UpdateSyncState updates the wallet's sync state. If a birthday block is
// provided, it will also be updated.
func (d *KvdbStore) UpdateSyncState(ctx context.Context, params UpdateSyncStateParams) error {
	return walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		bs := waddrmgr.BlockStamp{
			Hash:      params.SyncState.SyncedTo,
			Height:    params.SyncState.Height,
			Timestamp: params.SyncState.Timestamp,
		}
		err := d.addrStore.SetSyncedTo(addrmgrNs, &bs)
		if err != nil {
			return err
		}

		if params.BirthdayBlock != nil {
			err := d.addrStore.SetBirthdayBlock(
				addrmgrNs, *params.BirthdayBlock, false,
			)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

// GetHDSeed is a placeholder for the GetHDSeed method.
func (d *KvdbStore) GetHDSeed(ctx context.Context, params GetHDSeedParams) ([]byte, error) {
	// TODO(yy): implement
	return nil, nil
}

// ChangePassphrase changes the passphrase of the wallet.
func (d *KvdbStore) ChangePassphrase(ctx context.Context, old, new []byte, private bool) error {
	return walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		return d.addrStore.ChangePassphrase(
			addrmgrNs, old, new, private,
			&waddrmgr.DefaultScryptOptions,
		)
	})
}

// Unlock unlocks the wallet.
func (d *KvdbStore) Unlock(ctx context.Context, passphrase []byte) error {
	return walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		return d.addrStore.Unlock(addrmgrNs, passphrase)
	})
}

// Lock locks the wallet.
func (d *KvdbStore) Lock(ctx context.Context) {
	d.addrStore.Lock()
}

// IsLocked returns true if the wallet is locked.
func (d *KvdbStore) IsLocked(ctx context.Context) bool {
	return d.addrStore.IsLocked()
}

// BirthdayBlock returns the birthday block of the wallet.
func (d *KvdbStore) BirthdayBlock(ctx context.Context) (waddrmgr.BlockStamp, bool, error) {
	var bs waddrmgr.BlockStamp
	var verified bool
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error
		bs, verified, err = BirthdayBlock(addrmgrNs)
		return err
	})
	return bs, verified, err
}

// SetBirthday sets the birthday of the wallet.
func (d *KvdbStore) SetBirthday(ctx context.Context, birthday time.Time) error {
	return walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		return PutBirthday(addrmgrNs, birthday)
	})
}

// SetBirthdayBlock sets the birthday block of the wallet.
func (d *KvdbStore) SetBirthdayBlock(ctx context.Context, block waddrmgr.BlockStamp, verified bool) error {
	return walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		return PutBirthdayBlock(addrmgrNs, block, verified)
	})
}

// ============================================================================
// AccountStore Implementation
// ============================================================================

// CreateAccount creates a new account and returns its properties.
func (d *KvdbStore) CreateAccount(ctx context.Context, params CreateAccountParams) (AccountInfo, error) {
	var info AccountInfo
	err := walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		scope := fromDBKeyScope(params.Scope)

		manager, err := d.addrStore.FetchScopedKeyManager(scope)
		if err != nil {
			return err
		}

		// Validate that the scope manager can add this new account.
		err = manager.CanAddAccount()
		if err != nil {
			return err
		}

		// Create a new account under the current key scope.
		accNum, err := manager.NewAccount(addrmgrNs, params.Name)
		if err != nil {
			return err
		}

		// Get the account's properties.
		props, err := manager.AccountProperties(addrmgrNs, accNum)
		if err != nil {
			return err
		}

		info = AccountInfo{
			AccountNumber:    props.AccountNumber,
			AccountName:      props.AccountName,
			ExternalKeyCount: props.ExternalKeyCount,
			InternalKeyCount: props.InternalKeyCount,
			ImportedKeyCount: props.ImportedKeyCount,
			// Balances will be zero for a new account.
		}
		return nil
	})
	if err != nil {
		return AccountInfo{}, err
	}

	return info, nil
}

// ImportAccount imports an account from an extended key.
func (d *KvdbStore) ImportAccount(ctx context.Context, params ImportAccountParams) (AccountInfo, error) {
	// TODO(yy): The original implementation called a deprecated method.
	// We need to re-implement this using the modern waddrmgr functions.
	// For now, we'll just return a placeholder.
	return AccountInfo{}, errors.New("ImportAccount not implemented")
}

// GetAccount retrieves the details for a specific account.
func (d *KvdbStore) GetAccount(ctx context.Context, query GetAccountQuery) (AccountInfo, error) {
	var info AccountInfo
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		scope := fromDBKeyScope(query.Scope)

		manager, err := d.addrStore.FetchScopedKeyManager(scope)
		if err != nil {
			return err
		}

		// Look up the account number for the given name and scope.
		accNum, err := manager.LookupAccount(addrmgrNs, *query.Name)
		if err != nil {
			return err
		}

		// Retrieve the static properties for the account.
		props, err := manager.AccountProperties(addrmgrNs, accNum)
		if err != nil {
			return err
		}

		// Calculate the balances for this specific account.
		scopedBalances, err := d.fetchAccountBalances(
			tx, withScope(scope),
		)
		if err != nil {
			return err
		}

		info = AccountInfo{
			AccountNumber:    props.AccountNumber,
			AccountName:      props.AccountName,
			ExternalKeyCount: props.ExternalKeyCount,
			InternalKeyCount: props.InternalKeyCount,
			ImportedKeyCount: props.ImportedKeyCount,
		}

		// Assign the balances to the account result.
		if balances, ok := scopedBalances[scope]; ok {
			info.ConfirmedBalance = balances[accNum].confirmed
			info.UnconfirmedBalance = balances[accNum].unconfirmed
		}

		return nil
	})
	if err != nil {
		return AccountInfo{}, err
	}

	return info, nil
}

// ListAccounts retrieves a list of all accounts, optionally filtered by
// scope or name.
func (d *KvdbStore) ListAccounts(ctx context.Context, query ListAccountsQuery) ([]AccountInfo, error) {
	var accounts []AccountInfo
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		// First, build a map of balances for all accounts that own at
		// least one UTXO.
		scopedBalances, err := d.fetchAccountBalances(tx)
		if err != nil {
			return err
		}

		// Now, iterate through each key scope to assemble the final list
		// of accounts with their properties and balances.
		scopes := d.addrStore.ActiveScopedKeyManagers()
		for _, scopeMgr := range scopes {
			scope := scopeMgr.Scope()

			// If a scope filter is provided, skip all other scopes.
			if query.Scope != nil && scope != fromDBKeyScope(*query.Scope) {
				continue
			}

			accountBalances := scopedBalances[scope]

			// For the current scope, retrieve the properties for
			// each account and combine them with the
			// pre-calculated balances.
			scopedAccounts, err := listAccountsWithBalances(
				scopeMgr, addrmgrNs, accountBalances,
			)
			if err != nil {
				return err
			}

			// If a name filter is provided, only include accounts
			// that match.
			if query.Name != nil {
				for _, acc := range scopedAccounts {
					if acc.AccountName == *query.Name {
						accounts = append(accounts, acc)
					}
				}
			} else {
				accounts = append(accounts, scopedAccounts...)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return accounts, nil
}

// UpdateAccountName renames an existing account.
func (d *KvdbStore) UpdateAccountName(ctx context.Context, params UpdateAccountNameParams) error {
	return walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		scope := fromDBKeyScope(params.Scope)

		manager, err := d.addrStore.FetchScopedKeyManager(scope)
		if err != nil {
			return err
		}

		// Look up the account number for the given name.
		accNum, err := manager.LookupAccount(addrmgrNs, params.OldName)
		if err != nil {
			return err
		}

		// Perform the rename operation.
		return manager.RenameAccount(addrmgrNs, accNum, params.NewName)
	})
}

// RenameAccount renames an account.
func (d *KvdbStore) RenameAccount(ctx context.Context, params RenameAccountParams) error {
	return walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		scope := fromDBKeyScope(params.Scope)

		manager, err := d.addrStore.FetchScopedKeyManager(scope)
		if err != nil {
			return err
		}

		return manager.RenameAccount(addrmgrNs, params.AccountNumber, params.NewName)
	})
}

// FetchScopedKeyManager returns the scoped key manager for the given scope.
func (d *KvdbStore) FetchScopedKeyManager(scope KeyScope) (waddrmgr.AccountStore, error) {
	return d.addrStore.FetchScopedKeyManager(fromDBKeyScope(scope))
}

// NewScopedKeyManager creates a new scoped key manager.
func (d *KvdbStore) NewScopedKeyManager(scope KeyScope, addrSchema waddrmgr.ScopeAddrSchema) (waddrmgr.AccountStore, error) {
	var mgr waddrmgr.AccountStore
	err := walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		var err error
		mgr, err = d.addrStore.NewScopedKeyManager(addrmgrNs, fromDBKeyScope(scope), addrSchema)
		return err
	})
	return mgr, err
}

// ============================================================================
// AddressStore Implementation
// ============================================================================

// CreateAddress creates a new address for the given account and address type.
func (d *KvdbStore) CreateAddress(ctx context.Context, params CreateAddressParams) (AddressInfo, error) {
	var managedAddr waddrmgr.ManagedAddress
	err := walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		scope := fromDBKeyScope(params.Scope)

		manager, err := d.addrStore.FetchScopedKeyManager(scope)
		if err != nil {
			return err
		}

		addr, err := manager.NewAddress(addrmgrNs, params.AccountName, params.Change)
		if err != nil {
			return err
		}

		managedAddr, err = d.addrStore.Address(addrmgrNs, addr)
		return err
	})
	if err != nil {
		return AddressInfo{}, err
	}

	return toDBAddressInfo(managedAddr), nil
}

// ImportAddress imports a public key, taproot script, or generic script as a
// watch-only address.
func (d *KvdbStore) ImportAddress(ctx context.Context, params ImportAddressData) (AddressInfo, error) {
	var addr waddrmgr.ManagedAddress
	err := walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		syncedTo := d.addrStore.SyncedTo()
		manager, err := d.addrStore.FetchScopedKeyManager(fromDBKeyScope(params.Scope))
		if err != nil {
			return err
		}

		switch {
		case params.PubKey != nil:
			addr, err = manager.ImportPublicKey(ns, params.PubKey, &syncedTo)
			return err

		case params.Tapscript != nil:
			controlBlock, err := txscript.ParseControlBlock(params.Tapscript.ControlBlock)
			if err != nil {
				return err
			}
			tapscript := waddrmgr.Tapscript{
				ControlBlock: controlBlock,
				Leaves:       []txscript.TapLeaf{{Script: params.Tapscript.Script}},
			}
			addr, err = manager.ImportTaprootScript(ns, &tapscript, &syncedTo, 1, false)
			return err

		case params.Script != nil:
			addr, err = manager.ImportScript(ns, params.Script, &syncedTo)
			return err

		default:
			return errors.New("no import data provided")
		}
	})
	if err != nil {
		return AddressInfo{}, err
	}

	return toDBAddressInfo(addr), nil
}

// GetAddress retrieves the details for a specific address.
func (d *KvdbStore) GetAddress(ctx context.Context, query GetAddressQuery) (AddressInfo, error) {
	var managedAddress waddrmgr.ManagedAddress
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error
		managedAddress, err = d.addrStore.Address(addrmgrNs, query.Address)
		return err
	})
	if err != nil {
		return AddressInfo{}, err
	}

	return toDBAddressInfo(managedAddress), nil
}

// ListAddresses lists all addresses for a given account.
func (d *KvdbStore) ListAddresses(ctx context.Context, query ListAddressesQuery) ([]AddressInfo, error) {
	var addresses []AddressInfo
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		scope := fromDBKeyScope(query.Scope)

		manager, err := d.addrStore.FetchScopedKeyManager(scope)
		if err != nil {
			return err
		}

		acctNum, err := manager.LookupAccount(addrmgrNs, query.AccountName)
		if err != nil {
			return err
		}

		return manager.ForEachAccountAddress(addrmgrNs, acctNum,
			func(maddr waddrmgr.ManagedAddress) error {
				addresses = append(addresses, toDBAddressInfo(maddr))
				return nil
			})
	})
	if err != nil {
		return nil, err
	}

	return addresses, nil
}

// MarkAddressAsUsed marks an address as used.
func (d *KvdbStore) MarkAddressAsUsed(ctx context.Context, params MarkAddressAsUsedParams) error {
	return walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		return d.addrStore.MarkUsed(addrmgrNs, params.Address)
	})
}

// GetPrivateKey returns the private key for a given address.
func (d *KvdbStore) GetPrivateKey(ctx context.Context, addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
	var (
		privKey    *btcec.PrivateKey
		compressed bool
	)
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		ma, err := d.addrStore.Address(addrmgrNs, addr)
		if err != nil {
			return err
		}
		mpka, ok := ma.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return fmt.Errorf("managed address type for %v is `%T` but want waddrmgr.ManagedPubKeyAddress", addr, ma)
		}
		privKey, err = mpka.PrivKey()
		if err != nil {
			return err
		}
		compressed = ma.Compressed()
		return nil
	})
	return privKey, compressed, err
}

// DeriveFromKeyPath derives a managed address from a BIP-32 derivation path.
func (d *KvdbStore) DeriveFromKeyPath(ctx context.Context, scope KeyScope,
	path waddrmgr.DerivationPath) (waddrmgr.ManagedAddress, error) {
	var addr waddrmgr.ManagedAddress
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		dbScope := fromDBKeyScope(scope)
		manager, err := d.addrStore.FetchScopedKeyManager(dbScope)
		if err != nil {
			return err
		}
		addr, err = manager.DeriveFromKeyPath(addrmgrNs, path)
		return err
	})
	return addr, err
}

// NewAddress creates a new address.
func (d *KvdbStore) NewAddress(ctx context.Context, accountName string,
	addrType AddressType, withChange bool) (btcutil.Address, error) {
	var addr btcutil.Address
	err := walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		// TODO(yy): get scope from somewhere else
		scope := waddrmgr.KeyScopeBIP0084
		manager, err := d.addrStore.FetchScopedKeyManager(scope)
		if err != nil {
			return err
		}
		addr, err = manager.NewAddress(addrmgrNs, accountName, withChange)
		return err
	})
	return addr, err
}

// ============================================================================
// TxStore Implementation
// ============================================================================

// CreateTx atomically records a transaction and its associated credits.
func (d *KvdbStore) CreateTx(ctx context.Context, params CreateTxParams) error {
	txRec, err := wtxmgr.NewTxRecordFromMsgTx(params.Tx, time.Now())
	if err != nil {
		return err
	}

	return walletdb.Update(d.db, func(dbTx walletdb.ReadWriteTx) error {
		addrmgrNs := dbTx.ReadWriteBucket(waddrmgrNamespaceKey)
		txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)

		if len(params.Label) != 0 {
			txHash := txRec.MsgTx.TxHash()
			err := wtxmgr.PutTxLabel(txmgrNs, txHash, params.Label)
			if err != nil {
				return err
			}
		}

		// check if the transaction already exists.
		if txmgrNs.NestedReadBucket(bucketUnmined).Get(txRec.Hash[:]) != nil {
			return nil
		}

		// Insert the unconfirmed transaction record.
		recVal, err := wtxmgr.ValueTxRecord(txRec)
		if err != nil {
			return err
		}
		err = txmgrNs.NestedReadWriteBucket(bucketUnmined).Put(txRec.Hash[:], recVal)
		if err != nil {
			return err
		}

		unminedCreditsBucket, err := txmgrNs.CreateBucketIfNotExists(bucketUnminedCredits)
		if err != nil {
			return err
		}

		for _, credit := range params.Credits {
			ma, err := d.addrStore.Address(addrmgrNs, credit.Address)
			if err != nil {
				return err
			}

			k := wtxmgr.CanonicalOutPoint(&txRec.Hash, credit.Index)
			v := wtxmgr.ValueUnminedCredit(
				btcutil.Amount(txRec.MsgTx.TxOut[credit.Index].Value),
				ma.Internal(),
			)
			err = unminedCreditsBucket.Put(k, v)
			if err != nil {
				return err
			}

			err = d.addrStore.MarkUsed(addrmgrNs, credit.Address)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

// UpdateTx is a placeholder for the UpdateTx method.
func (d *KvdbStore) UpdateTx(ctx context.Context, params UpdateTxParams) error {
	txHash := params.TxHash
	return walletdb.Update(d.db, func(dbTx walletdb.ReadWriteTx) error {
		txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)

		// If a label is provided, update the transaction label.
		if len(params.Data.Label) != 0 {
			if len(params.Data.Label) > TxLabelLimit {
				return errors.New("label too long")
			}

			labelsBucket, err := txmgrNs.CreateBucketIfNotExists(
				[]byte("labels"),
			)
			if err != nil {
				return err
			}

			labelLen := uint16(len(params.Data.Label))
			var buf bytes.Buffer
			var b [2]byte
			binary.BigEndian.PutUint16(b[:], labelLen)
			if _, err := buf.Write(b[:]); err != nil {
				return err
			}
			if _, err := buf.WriteString(params.Data.Label); err != nil {
				return err
			}
			err = labelsBucket.Put(txHash[:], buf.Bytes())
			if err != nil {
				return err
			}
		}

		// TODO(yy): update block meta
		return nil
	})
}

// GetTx is a placeholder for the GetTx method.
func (d *KvdbStore) GetTx(ctx context.Context, query GetTxQuery) (TxInfo, error) {
	// TODO(yy): implement
	return TxInfo{}, nil
}

// ListTxs is a placeholder for the ListTxs method.
func (d *KvdbStore) ListTxs(ctx context.Context, query ListTxsQuery) ([]TxInfo, error) {
	// TODO(yy): implement
	return nil, nil
}

// UnminedTxs returns all unmined transactions.
func (d *KvdbStore) UnminedTxs(ctx context.Context) ([]*wire.MsgTx, error) {
	var txs []*wire.MsgTx
	err := walletdb.View(d.db, func(dbTx walletdb.ReadTx) error {
		txmgrNs := dbTx.ReadBucket(wtxmgrNamespaceKey)
		var err error
		txs, err = UnminedTxs(txmgrNs)
		return err
	})
	if err != nil {
		return nil, err
	}
	return txs, nil
}

// UnminedTxHashes returns the hashes of all unmined transactions.
func (d *KvdbStore) UnminedTxHashes(ctx context.Context) ([]*chainhash.Hash, error) {
	var hashes []*chainhash.Hash
	err := walletdb.View(d.db, func(dbTx walletdb.ReadTx) error {
		txmgrNs := dbTx.ReadBucket(wtxmgrNamespaceKey)
		var err error
		hashes, err = UnminedTxHashes(txmgrNs)
		return err
	})
	if err != nil {
		return nil, err
	}
	return hashes, nil
}

// DeleteTx removes an unmined transaction from the store.
func (d *KvdbStore) DeleteTx(ctx context.Context, params DeleteTxParams) error {
	return walletdb.Update(d.db, func(dbTx walletdb.ReadWriteTx) error {
		txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)

		txRec, err := wtxmgr.NewTxRecordFromMsgTx(params.Tx, time.Now())
		if err != nil {
			return err
		}

		return removeConflict(txmgrNs, txRec)
	})
}

// Rollback removes all blocks at height onwards, moving any transactions within
// each block to the unconfirmed pool.
func (d *KvdbStore) Rollback(ctx context.Context, height int32) error {
	return walletdb.Update(d.db, func(dbTx walletdb.ReadWriteTx) error {
		txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)
		return rollback(txmgrNs, height)
	})
}

// Balance returns the spendable wallet balance.
func (d *KvdbStore) Balance(ctx context.Context, minConfirms int32) (btcutil.Amount, error) {
	var balance btcutil.Amount
	err := walletdb.View(d.db, func(dbTx walletdb.ReadTx) error {
		txmgrNs := dbTx.ReadBucket(wtxmgrNamespaceKey)
		syncBlock := d.addrStore.SyncedTo()
		var err error
		balance, err = calculateBalance(txmgrNs, minConfirms, syncBlock.Height, d.addrStore.ChainParams())
		return err
	})
	return balance, err
}

// ============================================================================
// UTXOStore Implementation
// ============================================================================

// ListUTXOs returns all unspent transaction outputs.
func (d *KvdbStore) ListUTXOs(ctx context.Context, query ListUtxosQuery) ([]UtxoInfo, error) {
	var utxos []UtxoInfo
	err := walletdb.View(d.db, func(dbTx walletdb.ReadTx) error {
		txmgrNs := dbTx.ReadBucket(wtxmgrNamespaceKey)
		credits, err := wtxmgr.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}

		utxos = make([]UtxoInfo, len(credits))
		for i, credit := range credits {
			utxos[i] = UtxoInfo{
				OutPoint:     credit.OutPoint,
				Amount:       credit.Amount,
				PkScript:     credit.PkScript,
				Received:     credit.Received,
				FromCoinBase: credit.FromCoinBase,
				Height:       credit.BlockMeta.Height,
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return utxos, nil
}

// LeaseOutput locks an output for a given duration.
func (d *KvdbStore) LeaseOutput(ctx context.Context, id wtxmgr.LockID, op wire.OutPoint,
	duration time.Duration) (time.Time, error) {
	var expiration time.Time
	err := walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		var err error
		expiration, err = wtxmgr.LockOutput(txmgrNs, id, op, duration)
		return err
	})
	return expiration, err
}

// ReleaseOutput unlocks a previously leased output.
func (d *KvdbStore) ReleaseOutput(ctx context.Context, id wtxmgr.LockID, op wire.OutPoint) error {
	return walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		return wtxmgr.UnlockOutput(txmgrNs, id, op)
	})
}

// ListLeasedOutputs returns a list of all currently leased outputs.
func (d *KvdbStore) ListLeasedOutputs(ctx context.Context) ([]*wtxmgr.LockedOutput, error) {
	var leasedOutputs []*wtxmgr.LockedOutput
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		var err error
		leasedOutputs, err = wtxmgr.ListLockedOutputs(txmgrNs)
		return err
	})
	return leasedOutputs, err
}

// ============================================================================
// Balance Calculation Helpers
// ============================================================================

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
type scopedBalances map[waddrmgr.KeyScope]map[uint32]balance

// fetchAccountBalances creates a nested map of account balances, keyed by scope
// and account number.
func (d *KvdbStore) fetchAccountBalances(tx walletdb.ReadTx,
	opts ...filterOption) (scopedBalances, error) {

	// Apply the filter options.
	filter := &accountFilter{}
	for _, opt := range opts {
		opt(filter)
	}

	addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
	txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

	// First, fetch all unspent outputs.
	utxos, err := wtxmgr.UnspentOutputs(txmgrNs)
	if err != nil {
		return nil, err
	}

	// Now, create the nested map to hold the balances.
	scopedBalances := make(scopedBalances)
	_ = d.addrStore.SyncedTo()

	// Iterate through all UTXOs, mapping them back to their owning account
	// to aggregate the total balance for each.
	for _, utxo := range utxos {
		// TODO(yy): get chain params from somewhere else.
		addr := extractAddrFromPKScript(utxo.PkScript, nil)
		if addr == nil {
			continue
		}

		// Now that we have the address, we'll look up which account it
		// belongs to.
		scope, accNum, err := d.addrStore.AddrAccount(addrmgrNs, addr)
		if err != nil {
			continue
		}

		// If a scope filter was provided, apply it now.
		if filter.scope != nil {
			if scope.Scope() != *filter.scope {
				continue
			}
		}

		keyScope := scope.Scope()
		if _, ok := scopedBalances[keyScope]; !ok {
			scopedBalances[keyScope] = make(map[uint32]balance)
		}

		// Add the UTXO's value to the account's balance.
		currentBalance := scopedBalances[keyScope][accNum]
		if utxo.Height == -1 {
			currentBalance.unconfirmed += utxo.Amount
		} else {
			currentBalance.confirmed += utxo.Amount
		}
		scopedBalances[keyScope][accNum] = currentBalance
	}

	return scopedBalances, nil
}

// listAccountsWithBalances is a helper function that iterates through all
// accounts in a given scope, fetches their properties, and combines them with
// the provided account balances.
func listAccountsWithBalances(scopeMgr waddrmgr.AccountStore,
	addrmgrNs walletdb.ReadBucket,
	accountBalances map[uint32]balance) ([]AccountInfo, error) {

	var accounts []AccountInfo
	lastAccount, err := scopeMgr.LastAccount(addrmgrNs)
	if err != nil {
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return nil, nil
		}
		return nil, err
	}

	for accNum := uint32(0); accNum <= lastAccount; accNum++ {
		props, err := scopeMgr.AccountProperties(addrmgrNs, accNum)
		if err != nil {
			return nil, err
		}

		balance := accountBalances[accNum]
		accounts = append(accounts, AccountInfo{
			AccountNumber:      props.AccountNumber,
			AccountName:        props.AccountName,
			ExternalKeyCount:   props.ExternalKeyCount,
			InternalKeyCount:   props.InternalKeyCount,
			ImportedKeyCount:   props.ImportedKeyCount,
			ConfirmedBalance:   balance.confirmed,
			UnconfirmedBalance: balance.unconfirmed,
		})
	}

	return accounts, nil
}

// extractAddrFromPKScript extracts an address from a public key script.
func extractAddrFromPKScript(pkScript []byte,
	chainParams *chaincfg.Params) btcutil.Address {

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		pkScript, chainParams,
	)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	return addrs[0]
}

// fromDBKeyScope converts a db.KeyScope to a waddrmgr.KeyScope.
func fromDBKeyScope(scope KeyScope) waddrmgr.KeyScope {
	return waddrmgr.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
}

func toDBKeyScope(scope waddrmgr.KeyScope) KeyScope {
	return KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
}

func toDBAddressInfo(addr waddrmgr.ManagedAddress) AddressInfo {
	pubKeyAddr, ok := addr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return AddressInfo{
			Address:    addr.Address(),
			Internal:   addr.Internal(),
			Compressed: addr.Compressed(),
			Used:       addr.Used(nil), // This is a simplification
			AddrType:   AddressType(addr.AddrType()),
		}
	}

	scope, derivInfo, ok := pubKeyAddr.DerivationInfo()
	if !ok {
		return AddressInfo{
			Address:    addr.Address(),
			Internal:   addr.Internal(),
			Compressed: addr.Compressed(),
			Used:       addr.Used(nil), // This is a simplification
			AddrType:   AddressType(addr.AddrType()),
		}
	}

	return AddressInfo{
		Address:    addr.Address(),
		Internal:   addr.Internal(),
		Compressed: addr.Compressed(),
		Used:       addr.Used(nil), // This is a simplification
		AddrType:   AddressType(addr.AddrType()),
		DerivationInfo: DerivationInfo{
			KeyScope:             toDBKeyScope(scope),
			MasterKeyFingerprint: derivInfo.MasterKeyFingerprint,
			Account:              derivInfo.Account,
			Branch:               derivInfo.Branch,
			Index:                derivInfo.Index,
		},
	}
}