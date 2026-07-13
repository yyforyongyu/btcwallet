package kvdb

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/walletdb/migration"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// CreateLegacyWalletParams holds the legacy wallet initialization inputs.
type CreateLegacyWalletParams struct {
	// RootKey is the optional root extended key used to initialize waddrmgr.
	RootKey *hdkeychain.ExtendedKey

	// PubPassphrase is the public passphrase used by waddrmgr.
	PubPassphrase []byte

	// PrivatePassphrase is the private passphrase used by waddrmgr.
	PrivatePassphrase []byte

	// ChainParams identifies the wallet chain parameters.
	ChainParams *chaincfg.Params

	// Birthday is the wallet birthday persisted in waddrmgr.
	Birthday time.Time
}

// ChangePassphraseParams holds legacy public/private passphrase rotation
// inputs.
type ChangePassphraseParams struct {
	// ChangePublic controls whether the public passphrase is rotated.
	ChangePublic bool

	// PublicOld is the current public passphrase.
	PublicOld []byte

	// PublicNew is the replacement public passphrase.
	PublicNew []byte

	// ChangePrivate controls whether the private passphrase is rotated.
	ChangePrivate bool

	// PrivateOld is the current private passphrase.
	PrivateOld []byte

	// PrivateNew is the replacement private passphrase.
	PrivateNew []byte
}

// CreateLegacyWallet initializes the legacy walletdb bucket structure for a
// new wallet.
func CreateLegacyWallet(dbConn walletdb.DB,
	params CreateLegacyWalletParams) error {

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		addrMgrNs, err := tx.CreateTopLevelBucket(waddrmgr.NamespaceKey)
		if err != nil {
			return fmt.Errorf("create addr mgr bucket: %w", err)
		}

		txMgrNs, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if err != nil {
			return fmt.Errorf("create tx mgr bucket: %w", err)
		}

		err = waddrmgr.Create(
			addrMgrNs, params.RootKey, params.PubPassphrase,
			params.PrivatePassphrase, params.ChainParams, nil,
			params.Birthday,
		)
		if err != nil {
			return fmt.Errorf("create addr mgr: %w", err)
		}

		err = wtxmgr.Create(txMgrNs)
		if err != nil {
			return fmt.Errorf("create tx mgr: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	return nil
}

// LoadLegacyWallet upgrades and opens the legacy address and transaction
// managers from walletdb.
func LoadLegacyWallet(dbConn walletdb.DB, pubPassphrase []byte,
	chainParams *chaincfg.Params) (*waddrmgr.Manager, *wtxmgr.Store, error) {

	var (
		addrMgr *waddrmgr.Manager
		txMgr   *wtxmgr.Store
	)

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		addrMgrBucket := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if addrMgrBucket == nil {
			return errMissingAddrmgrNamespace
		}

		txMgrBucket := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if txMgrBucket == nil {
			return errMissingTxmgrNamespace
		}

		addrMgrUpgrader := waddrmgr.NewMigrationManager(addrMgrBucket)
		txMgrUpgrader := wtxmgr.NewMigrationManager(txMgrBucket)

		err := migration.Upgrade(txMgrUpgrader, addrMgrUpgrader)
		if err != nil {
			return fmt.Errorf("failed to upgrade database: %w", err)
		}

		addrMgr, err = waddrmgr.Open(
			addrMgrBucket, pubPassphrase, chainParams,
		)
		if err != nil {
			return fmt.Errorf("failed to open address manager: %w", err)
		}

		txMgr, err = wtxmgr.Open(txMgrBucket, chainParams)
		if err != nil {
			return fmt.Errorf("failed to open transaction manager: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load wallet: %w", err)
	}

	return addrMgr, txMgr, nil
}

// ChangePassphrase rotates the legacy address manager public and/or private
// passphrases within one kvdb write transaction.
func (s *Store) ChangePassphrase(ctx context.Context,
	params ChangePassphraseParams) error {

	err := checkContext(ctx)
	if err != nil {
		return err
	}

	if s.addrStore == nil {
		return fmt.Errorf("kvdb.Store.ChangePassphrase: %w",
			errMissingAddrStore)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if addrmgrNs == nil {
			return errMissingAddrmgrNamespace
		}

		if params.ChangePublic {
			err := s.addrStore.ChangePassphrase(
				addrmgrNs, params.PublicOld, params.PublicNew,
				false, &waddrmgr.DefaultScryptOptions,
			)
			if err != nil {
				return fmt.Errorf("change public passphrase: %w", err)
			}
		}

		if params.ChangePrivate {
			err := s.addrStore.ChangePassphrase(
				addrmgrNs, params.PrivateOld, params.PrivateNew,
				true, &waddrmgr.DefaultScryptOptions,
			)
			if err != nil {
				return fmt.Errorf("change private passphrase: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.ChangePassphrase: %w", err)
	}

	return nil
}
