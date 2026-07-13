package wallet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
)

// defaultSQLiteDirPerm is the permission applied to the directory created for
// the SQLite runtime store, mirroring the kvdb driver.
const defaultSQLiteDirPerm = 0o700

var runtimeStoreFactory = openRuntimeStore

// runtimeStoreHandle is the constructed runtime store plus metadata loaded
// from the same backend.
type runtimeStoreHandle struct {
	store      db.Store
	walletInfo *db.WalletInfo
	closeFn    func() error
}

// close closes the runtime store if this handle owns one.
func (h *runtimeStoreHandle) close() error {
	if h == nil || h.closeFn == nil {
		return nil
	}

	err := h.closeFn()
	h.closeFn = nil

	if err != nil {
		return fmt.Errorf("close runtime store: %w", err)
	}

	return nil
}

// closeAfterError closes an owned runtime store while preserving err as the
// primary failure.
func (h *runtimeStoreHandle) closeAfterError(err error) error {
	closeErr := h.close()
	if closeErr != nil {
		return errors.Join(err, closeErr)
	}

	return err
}

// masterFingerprint parses the runtime wallet's master HD public key and
// returns its BIP32 fingerprint. Shell, watch-only, and pre-master-key wallets
// have no pubkey persisted, so the fingerprint is zero.
func (h *runtimeStoreHandle) masterFingerprint() (uint32, error) {
	if h.walletInfo == nil || len(h.walletInfo.MasterPubKey) == 0 {
		return 0, nil
	}

	extKey, err := hdkeychain.NewKeyFromString(
		string(h.walletInfo.MasterPubKey),
	)
	if err != nil {
		return 0, fmt.Errorf("parse master HD pubkey: %w", err)
	}

	mfp, err := masterKeyFingerprint(extKey)
	if err != nil {
		return 0, fmt.Errorf("master fingerprint: %w", err)
	}

	return mfp, nil
}

// openRuntimeStore constructs the configured runtime store and loads the
// wallet row that will identify all store-backed wallet operations.
func openRuntimeStore(ctx context.Context, cfg Config,
	legacyStore *kvdb.StoreHandle) (*runtimeStoreHandle, error) {

	runtimeCfg := cfg.DB.withDefaults()

	err := runtimeCfg.Validate()
	if err != nil {
		return nil, err
	}

	switch runtimeCfg.Backend {
	case DBBackendKVDB:
		if legacyStore == nil {
			return nil, fmt.Errorf("%w: legacy store", ErrMissingParam)
		}

		return loadRuntimeWallet(ctx, legacyStore.Store, nil, cfg.Name)

	case DBBackendSQLite:
		// Unlike the kvdb driver, sqlite.NewStore does not create the parent
		// directory, so ensure it exists before opening.
		err := os.MkdirAll(
			filepath.Dir(runtimeCfg.SQLite.DBPath), defaultSQLiteDirPerm,
		)
		if err != nil {
			return nil, fmt.Errorf("create sqlite dir: %w", err)
		}

		store, err := sqlite.NewStore(ctx, sqlite.Config{
			DBPath:         runtimeCfg.SQLite.DBPath,
			MaxConnections: runtimeCfg.SQLite.MaxConnections,
			DeriveAddress:  newRuntimeAddressDeriver(cfg),
		})
		if err != nil {
			return nil, fmt.Errorf("open sqlite runtime store: %w", err)
		}

		return loadRuntimeWallet(ctx, store, store.Close, cfg.Name)

	case DBBackendPostgres:
		store, err := pg.NewStore(ctx, pg.Config{
			Dsn:            runtimeCfg.Postgres.DSN,
			MaxConnections: runtimeCfg.Postgres.MaxConnections,
			DeriveAddress:  newRuntimeAddressDeriver(cfg),
		})
		if err != nil {
			return nil, fmt.Errorf("open postgres runtime store: %w", err)
		}

		return loadRuntimeWallet(ctx, store, store.Close, cfg.Name)

	default:
		return nil, fmt.Errorf("%w: DB.Backend %q",
			ErrInvalidParam, runtimeCfg.Backend)
	}
}

// legacyKVDBConfig converts the wallet-level kvdb settings to the internal
// kvdb package config.
func legacyKVDBConfig(cfg Config) kvdb.Config {
	return kvdb.Config{
		DBPath:         cfg.DB.KVDB.DBPath,
		NoFreelistSync: cfg.DB.KVDB.NoFreelistSync,
		Timeout:        cfg.DB.KVDB.Timeout,
	}
}

// createRuntimeWallet creates the wallet row in the selected runtime database
// when the selected backend is SQL. The legacy kvdb backend reads wallet
// metadata directly from walletdb and does not need a separate row.
//
// It reports whether a runtime row with this name already existed, so Create
// can distinguish a fresh SQL create from a retry over an existing SQL row. The
// kvdb backend has no separate row, so it always reports false.
func createRuntimeWallet(ctx context.Context, cfg Config,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey,
	birthday time.Time) (bool, error) {

	runtimeCfg := cfg.DB.withDefaults()

	err := runtimeCfg.Validate()
	if err != nil {
		return false, err
	}

	switch runtimeCfg.Backend {
	case DBBackendKVDB:
		return false, nil

	case DBBackendSQLite:
		// Unlike the kvdb driver, sqlite.NewStore does not create the parent
		// directory, so ensure it exists before opening.
		err := os.MkdirAll(
			filepath.Dir(runtimeCfg.SQLite.DBPath), defaultSQLiteDirPerm,
		)
		if err != nil {
			return false, fmt.Errorf("create sqlite dir: %w", err)
		}

		store, err := sqlite.NewStore(ctx, sqlite.Config{
			DBPath:         runtimeCfg.SQLite.DBPath,
			MaxConnections: runtimeCfg.SQLite.MaxConnections,
			DeriveAddress:  newRuntimeAddressDeriver(cfg),
		})
		if err != nil {
			return false, fmt.Errorf("open sqlite runtime store: %w",
				err)
		}

		defer func() {
			_ = store.Close()
		}()

		return createRuntimeWalletWithStore(
			ctx, store, cfg, params, rootKey, birthday,
		)

	case DBBackendPostgres:
		store, err := pg.NewStore(ctx, pg.Config{
			Dsn:            runtimeCfg.Postgres.DSN,
			MaxConnections: runtimeCfg.Postgres.MaxConnections,
			DeriveAddress:  newRuntimeAddressDeriver(cfg),
		})
		if err != nil {
			return false, fmt.Errorf("open postgres runtime "+
				"store: %w", err)
		}

		defer func() {
			_ = store.Close()
		}()

		return createRuntimeWalletWithStore(
			ctx, store, cfg, params, rootKey, birthday,
		)

	default:
		return false, fmt.Errorf("%w: DB.Backend %q", ErrInvalidParam,
			runtimeCfg.Backend)
	}
}

// createRuntimeWalletWithStore creates a runtime wallet row unless an existing
// row with the same name is already present. It reports whether the row
// already existed.
func createRuntimeWalletWithStore(ctx context.Context, store db.Store,
	cfg Config, params CreateWalletParams,
	rootKey *hdkeychain.ExtendedKey, birthday time.Time) (bool, error) {

	info, err := store.GetWallet(ctx, cfg.Name)
	if err == nil {
		err = verifyRootKeyMatchesRuntime(info, cfg.Name, rootKey,
			params.WatchOnly)
		if err != nil {
			return false, err
		}

		return true, nil
	}

	if !errors.Is(err, db.ErrWalletNotFound) {
		return false, fmt.Errorf("get runtime wallet: %w", err)
	}

	createParams, err := runtimeCreateWalletParams(
		cfg, params, rootKey, birthday,
	)
	if err != nil {
		return false, err
	}

	_, err = store.CreateWallet(ctx, createParams)
	if err != nil {
		return false, fmt.Errorf("create runtime wallet: %w", err)
	}

	return false, nil
}

// runtimeCreateWalletParams converts wallet creation inputs into the SQL
// runtime wallet metadata and secret rows. birthday is the final timestamp to
// persist (the caller has already applied the safety margin or resolved a retry
// birthday), so it is stored verbatim.
func runtimeCreateWalletParams(cfg Config, params CreateWalletParams,
	rootKey *hdkeychain.ExtendedKey, birthday time.Time) (
	db.CreateWalletParams, error) {

	createParams := db.CreateWalletParams{
		Name: cfg.Name,
		IsImported: params.Mode == ModeImportSeed ||
			params.Mode == ModeImportExtKey,
		//nolint:gosec // LatestMgrVersion is a small constant that fits int32.
		ManagerVersion: int32(waddrmgr.LatestMgrVersion),
		IsWatchOnly:    params.WatchOnly,
		Birthday:       birthday,
	}

	// A wallet created without a private root key (a rootless shell or
	// xpub-only mode) cannot sign, so it must be recorded as watch-only
	// regardless of the requested flag; otherwise a SQL load would mark its
	// UTXOs spendable even though the wallet holds no signing key.
	switch {
	case rootKey == nil:
		createParams.IsWatchOnly = true

	case rootKey.IsPrivate():
		masterPubKey, err := rootKey.Neuter()
		if err != nil {
			return db.CreateWalletParams{}, fmt.Errorf(
				"derive master HD pubkey: %w", err,
			)
		}

		createParams.MasterPubKey = []byte(masterPubKey.String())

	default:
		createParams.IsWatchOnly = true
		createParams.MasterPubKey = []byte(rootKey.String())
	}

	secrets, err := keyvault.CreateWalletSecrets(
		params.PrivatePassphrase, rootKey, createParams.IsWatchOnly,
	)
	if err != nil {
		return db.CreateWalletParams{}, fmt.Errorf(
			"create wallet secrets: %w", err,
		)
	}

	createParams.MasterKeyPrivParams = secrets.MasterPrivParams
	createParams.EncryptedCryptoPrivKey = secrets.EncryptedCryptoPrivKey
	createParams.EncryptedCryptoScriptKey = secrets.EncryptedCryptoScriptKey
	createParams.EncryptedMasterPrivKey = secrets.EncryptedMasterHdPrivKey

	return createParams, nil
}

// verifyRootKeyMatchesRuntime guards the SQL Create retry path against key
// material that differs from the already-created wallet row.
//
//nolint:cyclop // Keep retry-mode and key-material validation together.
func verifyRootKeyMatchesRuntime(info *db.WalletInfo, name string,
	rootKey *hdkeychain.ExtendedKey, watchOnly bool) error {

	if info == nil || len(info.MasterPubKey) == 0 {
		return nil
	}

	if info.IsWatchOnly {
		if rootKey == nil {
			return fmt.Errorf("%w: retry root key does not match the "+
				"existing wallet %q", ErrWalletParams, name)
		}

		if rootKey.IsPrivate() || !watchOnly {
			return fmt.Errorf("%w: retry cannot change the existing "+
				"watch-only wallet %q to spendable", ErrWalletParams,
				name)
		}
	} else if rootKey == nil || !rootKey.IsPrivate() || watchOnly {
		return fmt.Errorf("%w: retry cannot downgrade the existing "+
			"spendable wallet %q to watch-only; it requires a "+
			"matching private root key and WatchOnly=false",
			ErrWalletParams, name)
	}

	retryPub := rootKey
	if rootKey.IsPrivate() {
		var err error

		retryPub, err = rootKey.Neuter()
		if err != nil {
			return fmt.Errorf("neuter retry root key: %w", err)
		}
	}

	if retryPub.String() != string(info.MasterPubKey) {
		return fmt.Errorf("%w: retry root key does not match the "+
			"existing wallet %q", ErrWalletParams, name)
	}

	return nil
}

// birthdayWithSafetyMargin backs a requested birthday off by the legacy
// address manager's safety margin so the SQL runtime store persists the
// same timestamp the kvdb backend does. The stored birthday later drives
// both the birthday block and the initial SyncedTo tip, so without this
// margin a SQL-backed wallet could skip deposits made in the window just
// before the requested birthday. A zero birthday means "no birthday"
// (stored as NULL), so it is left untouched.
func birthdayWithSafetyMargin(birthday time.Time) time.Time {
	if birthday.IsZero() {
		return birthday
	}

	return birthday.Add(-waddrmgr.BirthdaySafetyMargin)
}

// loadRuntimeWallet loads the named wallet from store and closes owned stores
// when the wallet row is missing or unreadable.
func loadRuntimeWallet(ctx context.Context, store db.Store,
	closeFn func() error, walletName string) (*runtimeStoreHandle, error) {

	handle := &runtimeStoreHandle{
		store:   store,
		closeFn: closeFn,
	}

	info, err := store.GetWallet(ctx, walletName)
	if err != nil {
		return nil, handle.closeAfterError(
			fmt.Errorf("get runtime wallet: %w", err),
		)
	}

	handle.walletInfo = info

	return handle, nil
}

// newRuntimeAddressDeriver returns the SQL address derivation callback for a
// runtime store. The callback only needs static chain parameters, so it uses a
// minimal Wallet value rather than a fully assembled runtime wallet.
func newRuntimeAddressDeriver(cfg Config) db.AddressDerivationFunc {
	deriver := &Wallet{cfg: cfg}

	return deriver.deriveAddressData
}
