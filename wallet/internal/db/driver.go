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
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
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

// keyScopeFromPubKey returns the corresponding wallet key scope for the given
// extended public key. The address type can usually be inferred from the key's
// version, but may be required for certain keys to map them into the proper
// scope.
func keyScopeFromPubKey(pubKey *hdkeychain.ExtendedKey,
	addrType *waddrmgr.AddressType) (waddrmgr.KeyScope,
	*waddrmgr.ScopeAddrSchema, error) {

	switch waddrmgr.HDVersion(binary.BigEndian.Uint32(pubKey.Version())) {
	// For BIP-0044 keys, an address type must be specified as we intend to
	// not support importing BIP-0044 keys into the wallet using the legacy
	// pay-to-pubkey-hash (P2PKH) scheme. A nested witness address type will
	// force the standard BIP-0049 derivation scheme (nested witness pubkeys
	// everywhere), while a witness address type will force the standard
	// BIP-0084 derivation scheme.
	case waddrmgr.HDVersionMainNetBIP0044, waddrmgr.HDVersionTestNetBIP0044,
		waddrmgr.HDVersionSimNetBIP0044:

		if addrType == nil {
			return waddrmgr.KeyScope{}, nil, errors.New("address " +
				"type must be specified for account public " +
				"key with legacy version")
		}

		switch *addrType {
		case waddrmgr.NestedWitnessPubKey:
			return waddrmgr.KeyScopeBIP0049Plus,
				&waddrmgr.KeyScopeBIP0049AddrSchema, nil

		case waddrmgr.WitnessPubKey:
			return waddrmgr.KeyScopeBIP0084, nil, nil

		case waddrmgr.TaprootPubKey:
			return waddrmgr.KeyScopeBIP0086, nil, nil

		default:
			return waddrmgr.KeyScope{}, nil,
				fmt.Errorf("unsupported address type %v",
					*addrType)
		}

	// For BIP-0049 keys, we'll need to make a distinction between the
	// traditional BIP-0049 address schema (nested witness pubkeys
	// everywhere) and our own BIP-0049Plus address schema (nested
	// externally, witness internally).
	case waddrmgr.HDVersionMainNetBIP0049, waddrmgr.HDVersionTestNetBIP0049:
		if addrType == nil {
			return waddrmgr.KeyScope{}, nil, errors.New("address " +
				"type must be specified for account public " +
				"key with BIP-0049 version")
		}

		switch *addrType {
		case waddrmgr.NestedWitnessPubKey:
			return waddrmgr.KeyScopeBIP0049Plus,
				&waddrmgr.KeyScopeBIP0049AddrSchema, nil

		case waddrmgr.WitnessPubKey:
			return waddrmgr.KeyScopeBIP0049Plus, nil, nil

		default:
			return waddrmgr.KeyScope{}, nil,
				fmt.Errorf("unsupported address type %v",
					*addrType)
		}

	// BIP-0086 does not have its own SLIP-0132 HD version byte set (yet?).
	// So we either expect a user to import it with a BIP-0084 or BIP-0044
	// encoding.
	case waddrmgr.HDVersionMainNetBIP0084, waddrmgr.HDVersionTestNetBIP0084:
		if addrType == nil {
			return waddrmgr.KeyScope{}, nil, errors.New("address " +
				"type must be specified for account public " +
				"key with BIP-0084 version")
		}

		switch *addrType {
		case waddrmgr.WitnessPubKey:
			return waddrmgr.KeyScopeBIP0084, nil, nil

		case waddrmgr.TaprootPubKey:
			return waddrmgr.KeyScopeBIP0086, nil, nil

		default:
			return waddrmgr.KeyScope{}, nil,
				errors.New("address type mismatch")
		}

	default:
		return waddrmgr.KeyScope{}, nil, fmt.Errorf("unknown version %x",
			pubKey.Version())
	}
}

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

// A compile-time check to ensure that KvdbStore implements the granular store interfaces.
var _ WalletStore = (*KvdbStore)(nil)
var _ AccountStore = (*KvdbStore)(nil)
var _ AddressStore = (*KvdbStore)(nil)
var _ TxStore = (*KvdbStore)(nil)
var _ UTXOStore = (*KvdbStore)(nil)

// ============================================================================
// WalletStore Implementation
// ============================================================================

// CreateWallet is a placeholder for the CreateWallet method.
func (d *KvdbStore) CreateWallet(ctx context.Context, params CreateWalletParams) (*WalletInfo, error) {
	// TODO(yy): implement
	return nil, nil
}

// GetWallet is a placeholder for the GetWallet method.
func (d *KvdbStore) GetWallet(ctx context.Context, name string) (*WalletInfo, error) {
	// TODO(yy): implement
	return nil, nil
}

// ListWallets is a placeholder for the ListWallets method.
func (d *KvdbStore) ListWallets(ctx context.Context) ([]WalletInfo, error) {
	// TODO(yy): implement
	return nil, nil
}

// UpdateWallet is a placeholder for the UpdateWallet method.
func (d *KvdbStore) UpdateWallet(ctx context.Context, params UpdateWalletParams) error {
	// TODO(yy): implement
	return nil
}

// GetEncryptedHDSeed returns the encrypted HD seed of the wallet.
func (d *KvdbStore) GetEncryptedHDSeed(ctx context.Context, walletID uint64) ([]byte, error) {
	var encryptedSeed []byte
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		encryptedSeed, _ = FetchMasterHDKeys(addrmgrNs)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return encryptedSeed, nil
}

// ChangePassphrase changes the passphrase of the wallet.
func (d *KvdbStore) ChangePassphrase(ctx context.Context, params ChangePassphraseParams) error {
	return walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		// Get the encrypted keys and params from the address manager.
		encPubKey, encPrivKey, encScriptKey, masterKeyParams, err :=
			d.addrStore.PrepareChangePassphrase(
				params.OldPassphrase, params.NewPassphrase,
				params.IsPrivate, &waddrmgr.DefaultScryptOptions,
			)
		if err != nil {
			return err
		}

		// Write the new keys and params to the database.
		if params.IsPrivate {
			err = PutCryptoKeys(addrmgrNs, nil, encPrivKey, encScriptKey)
			if err != nil {
				return err
			}
			return PutMasterKeyParams(addrmgrNs, nil, masterKeyParams)
		}

		err = PutCryptoKeys(addrmgrNs, encPubKey, nil, nil)
		if err != nil {
			return err
		}
		return PutMasterKeyParams(addrmgrNs, masterKeyParams, nil)
	})
}

// ============================================================================
// AccountStore Implementation
// ============================================================================

// CreateAccount creates a new account and returns its properties.
func (d *KvdbStore) CreateAccount(ctx context.Context, params CreateAccountParams) (*AccountInfo, error) {
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
			KeyScope:         toDBKeyScope(scope),
			// Balances will be zero for a new account.
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &info, nil
}

// ImportAccount is a placeholder for the ImportAccount method.
func (d *KvdbStore) ImportAccount(ctx context.Context, params ImportAccountParams) (*ImportAccountResult, error) {
	// TODO(yy): implement
	return nil, nil
}

// GetAccount retrieves the details for a specific account.
func (d *KvdbStore) GetAccount(ctx context.Context, query GetAccountQuery) (*AccountInfo, error) {
	var info AccountInfo
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		scope := fromDBKeyScope(query.Scope)

		// Look up the account number for the given name and scope.
		scopedMgr, err := d.addrStore.FetchScopedKeyManager(scope)
		if err != nil {
			return err
		}
		accNum, err := scopedMgr.LookupAccount(addrmgrNs, *query.Name)
		if err != nil {
			return err
		}

		// Retrieve the static properties for the account.
		props, err := scopedMgr.AccountProperties(addrmgrNs, accNum)
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
			AccountNumber:    accNum,
			AccountName:      props.AccountName,
			ExternalKeyCount: props.ExternalKeyCount,
			InternalKeyCount: props.InternalKeyCount,
			ImportedKeyCount: props.ImportedKeyCount,
			IsWatchOnly:      props.IsWatchOnly,
			KeyScope:         toDBKeyScope(props.KeyScope),
		}

		// Assign the balances to the account result.
		if balances, ok := scopedBalances[scope]; ok {
			info.ConfirmedBalance = balances[accNum].confirmed
			info.UnconfirmedBalance = balances[accNum].unconfirmed
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &info, nil
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
				for i := range scopedAccounts {
					if scopedAccounts[i].AccountName == *query.Name {
						accounts = append(accounts, scopedAccounts[i])
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

// RenameAccount is a placeholder for the RenameAccount method.
func (d *KvdbStore) RenameAccount(ctx context.Context, params RenameAccountParams) error {
	// TODO(yy): implement
	return nil
}

// ============================================================================
// AddressStore Implementation
// ============================================================================

// NewAddress is a placeholder for the NewAddress method.
func (d *KvdbStore) NewAddress(ctx context.Context, params NewAddressParams) (btcutil.Address, error) {
	// TODO(yy): implement
	return nil, nil
}

// ImportAddress is a placeholder for the ImportAddress method.
func (d *KvdbStore) ImportAddress(ctx context.Context, params ImportAddressParams) (*AddressInfo, error) {
	// TODO(yy): implement
	return nil, nil
}

// GetAddress retrieves the details for a specific address.
func (d *KvdbStore) GetAddress(ctx context.Context, query GetAddressQuery) (*AddressInfo, error) {
	var managedAddress waddrmgr.ManagedAddress
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error
		managedAddress, err = d.addrStore.Address(addrmgrNs, query.Address)
		return err
	})
	if err != nil {
		return nil, err
	}

	info := toDBAddressInfo(managedAddress)
	return &info, nil
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

// GetPrivateKey retrieves the private key for a given address. This
// method is ONLY valid for addresses that were imported with a private
// key. It will return an error for derived HD addresses and watch-only
// imports.
func (d *KvdbStore) GetPrivateKey(ctx context.Context, params GetPrivateKeyParams) (*btcec.PrivateKey, error) {
	var privKey *btcec.PrivateKey
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		ma, err := d.addrStore.Address(addrmgrNs, params.Address)
		if err != nil {
			return err
		}
		mpka, ok := ma.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return fmt.Errorf("managed address type for %v is `%T` but want waddrmgr.ManagedPubKeyAddress", params.Address, ma)
		}
		privKey, err = mpka.PrivKey()
		if err != nil {
			return err
		}
		return nil
	})
	return privKey, err
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
	txid := params.Txid
	return walletdb.Update(d.db, func(dbTx walletdb.ReadWriteTx) error {
		txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)

		// If a label is provided, update the transaction label.
		if params.Label != nil {
			label := *params.Label
			if len(label) > TxLabelLimit {
				return errors.New("label too long")
			}

			labelsBucket, err := txmgrNs.CreateBucketIfNotExists(
				[]byte("labels"),
			)
			if err != nil {
				return err
			}

			labelLen := uint16(len(label))
			var buf bytes.Buffer
			var b [2]byte
			binary.BigEndian.PutUint16(b[:], labelLen)
			if _, err := buf.Write(b[:]); err != nil {
				return err
			}
			if _, err := buf.WriteString(label); err != nil {
				return err
			}
			err = labelsBucket.Put(txid[:], buf.Bytes())
			if err != nil {
				return err
			}
		}

		// If block metadata is provided, update the transaction's block
		// information.
		if params.Block != nil {
			// TODO(yy): update block meta
		}

		return nil
	})
}

// GetTx is a placeholder for the GetTx method.
func (d *KvdbStore) GetTx(ctx context.Context, query GetTxQuery) (*TxInfo, error) {
	// TODO(yy): implement
	return nil, nil
}

// ListTxns is a placeholder for the ListTxns method.
func (d *KvdbStore) ListTxns(ctx context.Context, query ListTxnsQuery) ([]TxInfo, error) {
	var txs []TxInfo
	err := walletdb.View(d.db, func(dbTx walletdb.ReadTx) error {
		txmgrNs := dbTx.ReadBucket(wtxmgrNamespaceKey)

		if query.UnminedOnly {
			unminedBucket := txmgrNs.NestedReadBucket(bucketUnmined)
			if unminedBucket == nil {
				return nil
			}

			return unminedBucket.ForEach(func(k, v []byte) error {
				var txHash chainhash.Hash
				copy(txHash[:], k)

				var txRec wtxmgr.TxRecord
				err := readRawTxRecord(&txHash, v, &txRec)
				if err != nil {
					return err
				}

				txs = append(txs, TxInfo{
					Hash:       txRec.Hash,
					SerializedTx: txRec.SerializedTx,
					Received:   txRec.Received,
					Block:      Block{Height: -1},
				})
				return nil
			})
		}

		// TODO(yy): implement listing mined transactions based on height range
		return nil
	})
	if err != nil {
		return nil, err
	}
	return txs, nil
}

// DeleteTx removes an unmined transaction from the store.
func (d *KvdbStore) DeleteTx(ctx context.Context, params DeleteTxParams) error {
	return walletdb.Update(d.db, func(dbTx walletdb.ReadWriteTx) error {
		txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)

		// TODO(yy): The removeConflict function in wtxmgr requires a
		// full TxRecord. We should consider updating it to accept just
		// a txid to avoid the need to fetch the full transaction here.
		// For now, we will just remove the tx from the unmined bucket.
		return txmgrNs.NestedReadWriteBucket(bucketUnmined).Delete(params.Txid[:])
	})
}

// RollbackToBlock removes all blocks at height onwards, moving any transactions within
// each block to the unconfirmed pool.
func (d *KvdbStore) RollbackToBlock(ctx context.Context, height int32) error {
	return walletdb.Update(d.db, func(dbTx walletdb.ReadWriteTx) error {
		txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)
		return rollback(txmgrNs, height)
	})
}

// ============================================================================
// UTXOStore Implementation
// ============================================================================

// GetUtxo is a placeholder for the GetUtxo method.
func (d *KvdbStore) GetUtxo(ctx context.Context, query GetUtxoQuery) (*UtxoInfo, error) {
	// TODO(yy): implement
	return nil, nil
}

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
func (d *KvdbStore) LeaseOutput(ctx context.Context, params LeaseOutputParams) (*LeasedOutput, error) {
	var expiration time.Time
	err := walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		var err error
		expiration, err = wtxmgr.LockOutput(
			txmgrNs, wtxmgr.LockID(params.ID), params.OutPoint,
			params.Duration,
		)
		return err
	})
	if err != nil {
		return nil, err
	}

	return &LeasedOutput{
		OutPoint:   params.OutPoint,
		LockID:     LockID(params.ID),
		Expiration: expiration,
	}, nil
}

// ReleaseOutput unlocks a previously leased output.
func (d *KvdbStore) ReleaseOutput(ctx context.Context, params ReleaseOutputParams) error {
	return walletdb.Update(d.db, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		return wtxmgr.UnlockOutput(
			txmgrNs, wtxmgr.LockID(params.ID), params.OutPoint,
		)
	})
}

// ListLeasedOutputs returns a list of all currently leased outputs.
func (d *KvdbStore) ListLeasedOutputs(ctx context.Context, walletID uint64) ([]LeasedOutput, error) {
	var leasedOutputs []LeasedOutput
	err := walletdb.View(d.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		wtxLeasedOutputs, err := wtxmgr.ListLockedOutputs(txmgrNs)
		if err != nil {
			return err
		}

		leasedOutputs = make([]LeasedOutput, len(wtxLeasedOutputs))
		for i, wtxLeasedOutput := range wtxLeasedOutputs {
			leasedOutputs[i] = LeasedOutput{
				OutPoint:   wtxLeasedOutput.Outpoint,
				LockID:     LockID(wtxLeasedOutput.LockID),
				Expiration: wtxLeasedOutput.Expiration,
			}
		}
		return nil
	})
	return leasedOutputs, err
}

// Balance returns the spendable wallet balance.
func (d *KvdbStore) Balance(ctx context.Context, params BalanceParams) (btcutil.Amount, error) {
	var balance btcutil.Amount
	err := walletdb.View(d.db, func(dbTx walletdb.ReadTx) error {
		txmgrNs := dbTx.ReadBucket(wtxmgrNamespaceKey)
		syncBlock := d.addrStore.SyncedTo()
		var err error
		balance, err = calculateBalance(
			txmgrNs, params.MinConfirms, syncBlock.Height,
			d.addrStore.ChainParams(),
		)
		return err
	})
	return balance, err
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

// LastAccount returns the last account number for a given scope.
func LastAccount(ns walletdb.ReadBucket, scope *waddrmgr.KeyScope) (uint32, error) {
	scopedBucket, err := fetchReadScopeBucket(ns, scope)
	if err != nil {
		return 0, err
	}

	metaBucket := scopedBucket.NestedReadBucket(metaBucketName)
	val := metaBucket.Get(lastAccountName)
	if val == nil {
		return 0, newError(ErrDatabase, "last account not found", nil)
	}
	if len(val) != 4 {
		return 0, newError(ErrDatabase, fmt.Sprintf("malformed metadata '%s' stored in database", lastAccountName), nil)
	}

	account := binary.LittleEndian.Uint32(val[0:4])
	return account, nil
}

// listAccountsWithBalances is a helper function that iterates through all
// accounts in a given scope, fetches their properties, and combines them with
// the provided account balances.
func listAccountsWithBalances(scopeMgr waddrmgr.AccountStore,
	addrmgrNs walletdb.ReadBucket,
	accountBalances map[uint32]balance) ([]AccountInfo, error) {

	var accounts []AccountInfo
	scope := scopeMgr.Scope()
	lastAccount, err := LastAccount(addrmgrNs, &scope)
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
			IsWatchOnly:        props.IsWatchOnly,
			KeyScope:           toDBKeyScope(props.KeyScope),
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
	info := AddressInfo{
		Address:    addr.Address(),
		Internal:   addr.Internal(),
		Compressed: addr.Compressed(),
		Used:       addr.Used(nil), // This is a simplification
		AddrType:   AddressType(addr.AddrType()),
	}

	// Check if the address is a public key address, which is required for
	// derivation info and watch-only status.
	pubKeyAddr, ok := addr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		// For other address types (like scripts), we can consider them
		// watch-only by default as they don't have a private key in the
		// same way.
		info.IsWatchOnly = true
		return info
	}

	// Determine if the address is watch-only by checking for the private
	// key.
	_, err := pubKeyAddr.PrivKey()
	info.IsWatchOnly = err != nil

	// If derivation info is available, populate it. Otherwise, it will
	// remain nil, correctly indicating an imported address.
	scope, derivInfo, ok := pubKeyAddr.DerivationInfo()
	if ok {
		info.DerivationInfo = &DerivationInfo{
			KeyScope:             toDBKeyScope(scope),
			MasterKeyFingerprint: derivInfo.MasterKeyFingerprint,
			Account:              derivInfo.Account,
			Branch:               derivInfo.Branch,
			Index:                derivInfo.Index,
		}
	}

	return info
}