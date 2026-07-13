package wallet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	kvdb "github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/stretchr/testify/require"
)

// errFakeStoreClose is a static test error for runtime store close failures.
var errFakeStoreClose = errors.New("fake runtime store close error")

// testWalletName is the wallet name shared by the runtime store tests.
const testWalletName = "test-wallet"

// createRuntimeStoreTestWallet creates one legacy walletdb wallet and returns a
// load config for it.
func createRuntimeStoreTestWallet(t *testing.T) Config {
	t.Helper()

	cfg := Config{
		DB:             testKVDBConfig(t),
		Chain:          &bwmock.Chain{},
		ChainParams:    &chainParams,
		Name:           testWalletName,
		PubPassphrase:  []byte("public"),
		RecoveryWindow: MinRecoveryWindow,
	}
	params := CreateWalletParams{
		Mode:              ModeGenSeed,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	w, err := NewManager().Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, w)
	require.NoError(t, w.closeRuntimeStore())

	return cfg
}

// TestManagerLoadUsesRuntimeStoreFactory verifies Manager.Load wires the
// selected runtime store and wallet metadata into the constructed wallet.
//
//nolint:paralleltest // Mutates the package-level runtimeStoreFactory.
func TestManagerLoadUsesRuntimeStoreFactory(t *testing.T) {
	cfg := createRuntimeStoreTestWallet(t)
	cfg.DB = DBConfig{
		KVDB:    cfg.DB.KVDB,
		Backend: DBBackendSQLite,
		SQLite: SQLiteDBConfig{
			DBPath: "unused.sqlite",
		},
	}

	oldFactory := runtimeStoreFactory
	t.Cleanup(func() {
		runtimeStoreFactory = oldFactory
	})

	store := &walletmock.Store{}
	called := false
	runtimeStoreFactory = func(_ context.Context, gotCfg Config,
		legacyStore *kvdb.StoreHandle) (*runtimeStoreHandle, error) {

		called = true

		require.Equal(t, cfg.Name, gotCfg.Name)
		require.Nil(t, legacyStore)

		return &runtimeStoreHandle{
			store: store,
			walletInfo: &db.WalletInfo{
				ID:          42,
				IsWatchOnly: true,
			},
		}, nil
	}

	w, err := NewManager().Load(cfg)
	require.NoError(t, err)
	require.True(t, called)
	require.Same(t, store, w.store)
	require.Equal(t, uint32(42), w.ID())
	require.True(t, w.IsWatchOnly())

	cache, ok := w.cache.(*storeRuntimeCache)
	require.True(t, ok)
	require.Same(t, store, cache.store)

	syncer, ok := w.sync.(*syncer)
	require.True(t, ok)
	require.Same(t, store, syncer.store)
	require.Equal(t, uint32(42), syncer.walletID)
}

// TestManagerLoadClosesRuntimeStoreOnMetadataError verifies that a constructed
// SQL runtime store is closed if wallet metadata parsing fails.
//
//nolint:paralleltest // Mutates the package-level runtimeStoreFactory.
func TestManagerLoadClosesRuntimeStoreOnMetadataError(t *testing.T) {
	cfg := createRuntimeStoreTestWallet(t)
	cfg.DB = DBConfig{
		KVDB:    cfg.DB.KVDB,
		Backend: DBBackendSQLite,
		SQLite: SQLiteDBConfig{
			DBPath: "unused.sqlite",
		},
	}

	oldFactory := runtimeStoreFactory
	t.Cleanup(func() {
		runtimeStoreFactory = oldFactory
	})

	closed := 0
	runtimeStoreFactory = func(context.Context, Config,
		*kvdb.StoreHandle) (*runtimeStoreHandle, error) {

		return &runtimeStoreHandle{
			store: &walletmock.Store{},
			walletInfo: &db.WalletInfo{
				ID:           42,
				MasterPubKey: []byte("not-an-xpub"),
			},
			closeFn: func() error {
				closed++
				return nil
			},
		}, nil
	}

	w, err := NewManager().Load(cfg)
	require.ErrorContains(t, err, "cache master fingerprint")
	require.Nil(t, w)
	require.Equal(t, 1, closed)
}

// TestOpenRuntimeStoreSQLiteRequiresWalletRow verifies the real SQLite factory
// fails closed instead of treating an empty SQL side database as authoritative.
func TestOpenRuntimeStoreSQLiteRequiresWalletRow(t *testing.T) {
	t.Parallel()

	cfg := createRuntimeStoreTestWallet(t)
	cfg.DB = DBConfig{
		KVDB:    cfg.DB.KVDB,
		Backend: DBBackendSQLite,
		SQLite: SQLiteDBConfig{
			DBPath: filepath.Join(t.TempDir(), "runtime.sqlite"),
		},
	}

	handle, err := openRuntimeStore(t.Context(), cfg, nil)
	require.ErrorIs(t, err, db.ErrWalletNotFound)
	require.Nil(t, handle)
}

// TestCloseRuntimeStore verifies the wallet-owned runtime store closer is
// idempotent.
func TestCloseRuntimeStore(t *testing.T) {
	t.Parallel()

	closed := 0
	w := &Wallet{
		runtimeStoreClose: func() error {
			closed++
			return nil
		},
	}

	require.NoError(t, w.closeRuntimeStore())
	require.NoError(t, w.closeRuntimeStore())
	require.Equal(t, 1, closed)
}

// TestCloseRuntimeStoreError verifies close errors are returned to callers.
func TestCloseRuntimeStoreError(t *testing.T) {
	t.Parallel()

	w := &Wallet{
		runtimeStoreClose: func() error {
			return errFakeStoreClose
		},
	}

	err := w.closeRuntimeStore()
	require.ErrorIs(t, err, errFakeStoreClose)
	require.NoError(t, w.closeRuntimeStore())
}

// sqliteCreateConfig returns a SQLite-backed create config and a spendable
// seed-import params pair sharing fresh temp paths, for tests that exercise
// the SQL create path end to end.
func sqliteCreateConfig(t *testing.T) (Config, CreateWalletParams) {
	t.Helper()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	dir := t.TempDir()
	cfg := Config{
		DB: DBConfig{
			KVDB:    KVDBConfig{DBPath: filepath.Join(dir, "wallet.db")},
			Backend: DBBackendSQLite,
			SQLite: SQLiteDBConfig{
				DBPath: filepath.Join(dir, "runtime.sqlite"),
			},
		},
		Chain:          &bwmock.Chain{},
		ChainParams:    &chainParams,
		Name:           testWalletName,
		PubPassphrase:  []byte("public"),
		RecoveryWindow: MinRecoveryWindow,
	}
	params := CreateWalletParams{
		Mode:              ModeImportSeed,
		Seed:              seed,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	return cfg, params
}

// requireNoLegacyWalletFile asserts that a SQL wallet did not create or open a
// walletdb sidecar at the configured kvdb path.
func requireNoLegacyWalletFile(t *testing.T, cfg Config) {
	t.Helper()

	_, err := os.Stat(cfg.DB.KVDB.DBPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

// startLoadedWalletForTest marks a loaded wallet as started without launching
// chain sync goroutines. Tests that exercise store-backed derivation use this
// to satisfy public API state checks while keeping the scope local to the
// store.
func startLoadedWalletForTest(t *testing.T, w *Wallet) {
	t.Helper()

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())
}

// TestRuntimeCreateWalletParamsCreatesSpendableSecrets verifies that SQL wallet
// creation parameters carry real encrypted secret material for spendable
// wallets.
func TestRuntimeCreateWalletParamsCreatesSpendableSecrets(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	got, err := runtimeCreateWalletParams(
		cfg, params, rootKey, birthdayWithSafetyMargin(params.Birthday),
	)
	require.NoError(t, err)

	require.NoError(t, got.Validate())
	require.NotEmpty(t, got.MasterKeyPrivParams)
	require.NotEmpty(t, got.EncryptedCryptoPrivKey)
	require.NotEmpty(t, got.EncryptedCryptoScriptKey)
	require.NotEmpty(t, got.EncryptedMasterPrivKey)
}

// TestManagerCreateLoadSQLiteNoLegacySidecar verifies a SQLite wallet can be
// created, reloaded, unlocked, and used for store-backed derivation without
// ever creating the legacy walletdb sidecar.
func TestManagerCreateLoadSQLiteNoLegacySidecar(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	w, err := NewManager().Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, w)
	require.Nil(t, w.addrStore)
	require.Nil(t, w.legacyStore)
	require.Nil(t, w.txStore)
	requireNoLegacyWalletFile(t, cfg)
	require.NoError(t, w.closeRuntimeStore())
	requireNoLegacyWalletFile(t, cfg)

	loaded, err := NewManager().Load(cfg)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	t.Cleanup(func() {
		require.NoError(t, loaded.closeRuntimeStore())
	})
	require.Nil(t, loaded.addrStore)
	require.Nil(t, loaded.legacyStore)
	require.Nil(t, loaded.txStore)
	requireNoLegacyWalletFile(t, cfg)

	startLoadedWalletForTest(t, loaded)
	require.NoError(t, loaded.keyVault.Unlock(
		t.Context(), params.PrivatePassphrase,
	))
	loaded.state.toUnlocked()

	path := BIP32Path{
		KeyScope: waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: 0,
			Account:         hdkeychain.HardenedKeyStart,
			Branch:          waddrmgr.ExternalBranch,
			Index:           0,
		},
	}

	pubKey, err := loaded.DerivePubKey(t.Context(), path)
	require.NoError(t, err)
	require.NotNil(t, pubKey)

	digest := make([]byte, 32)
	digest[0] = 1
	sig, err := loaded.SignDigest(t.Context(), path, &SignDigestIntent{
		Digest:  digest,
		SigType: SigTypeECDSA,
	})
	require.NoError(t, err)
	require.NotNil(t, sig)
	requireNoLegacyWalletFile(t, cfg)
}

// TestRuntimeCreateWalletParamsBirthdayVerbatim verifies that the SQL runtime
// create params persist the resolved birthday they are handed verbatim. The
// caller owns the margin decision (a fresh create supplies the requested
// birthday with the safety margin applied; a partial-create retry supplies the
// existing legacy wallet's original birthday), so this helper must not apply
// it a second time. A zero "no birthday" must pass through so it is persisted
// as NULL.
func TestRuntimeCreateWalletParamsBirthdayVerbatim(t *testing.T) {
	t.Parallel()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	// Warm the extended key's lazily-cached public key so the parallel
	// subtests below only read it; hdkeychain populates it on first use, which
	// would otherwise race across concurrent Neuter calls.
	_, err = rootKey.Neuter()
	require.NoError(t, err)

	requested := time.Date(2026, time.June, 16, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		birthday time.Time
	}{
		{
			name:     "resolved birthday is stored verbatim",
			birthday: requested.Add(-waddrmgr.BirthdaySafetyMargin),
		},
		{
			name:     "zero birthday is left untouched",
			birthday: time.Time{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a spendable seed-import create. A
			// non-empty private passphrase is required because
			// the store-backed key vault rejects an empty
			// passphrase for a spendable wallet.
			cfg := Config{Name: testWalletName}
			params := CreateWalletParams{
				Mode:              ModeImportSeed,
				PrivatePassphrase: []byte("private"),
			}

			// Act: build the SQL runtime create params with the
			// already-resolved birthday.
			got, err := runtimeCreateWalletParams(
				cfg, params, rootKey, tc.birthday,
			)
			require.NoError(t, err)

			// Assert: the stored birthday is exactly what was
			// passed in, with no further margin applied.
			require.Equal(t, tc.birthday, got.Birthday)
		})
	}
}

// TestBirthdayWithSafetyMargin verifies the helper subtracts exactly the legacy
// safety margin from a real birthday and passes a zero birthday through.
func TestBirthdayWithSafetyMargin(t *testing.T) {
	t.Parallel()

	birthday := time.Date(2026, time.June, 16, 0, 0, 0, 0, time.UTC)

	require.Equal(
		t, birthday.Add(-waddrmgr.BirthdaySafetyMargin),
		birthdayWithSafetyMargin(birthday),
	)
	require.True(t, birthdayWithSafetyMargin(time.Time{}).IsZero())
}

// TestSeedDefaultAccountsIdempotent verifies that re-running default-account
// seeding on a wallet whose default accounts already exist is a no-op rather
// than an error. A Create that failed after seeding only some scopes is
// retried against the same wallet, so replaying the seed for an already-seeded
// scope must not wedge on the unique (wallet, scope, name) constraint.
func TestSeedDefaultAccountsIdempotent(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	// Create the spendable SQL wallet; this seeds the default accounts once.
	w, err := NewManager().Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, w)
	t.Cleanup(func() {
		require.NoError(t, w.closeRuntimeStore())
	})

	// Re-running the seed (the retry path) must succeed without recreating
	// the already-present default accounts, reporting zero newly created.
	seeded, err := seedDefaultAccounts(
		t.Context(), w, rootKey, params.PrivatePassphrase,
	)
	require.NoError(t, err)
	require.Zero(t, seeded)

	// Each default scope must still hold exactly one default account, so
	// the idempotent re-run did not duplicate or renumber anything.
	for _, scope := range waddrmgr.DefaultKeyScopes {
		name := waddrmgr.DefaultAccountName
		info, err := w.store.GetAccount(t.Context(), db.GetAccountQuery{
			WalletID:    w.id,
			Scope:       db.KeyScope(scope),
			Name:        &name,
			SkipBalance: true,
		})
		require.NoError(t, err)
		require.Equal(t, waddrmgr.DefaultAccountName, info.AccountName)
		require.NotNil(t, info.AccountNumber)
		require.Equal(t, uint32(0), *info.AccountNumber)
	}
}

// TestManagerCreateRejectsExistingSQLWallet verifies that Create returns
// ErrWalletExists, rather than silently returning the existing wallet, only
// when the wallet is fully created: the legacy wallet and the SQL runtime row
// are present AND its post-load init (default-account seeding) is complete, so
// the idempotent replay has nothing left to do. A partial create whose rows
// exist but whose init the retry still completes is covered by
// TestManagerCreateRetryCompletesUnseededWallet, and the recoverable
// legacy-present/runtime-missing path by
// TestCreateRecoversSeedAfterPartialCreate.
func TestManagerCreateRejectsExistingSQLWallet(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	// Create the wallet end to end (rows plus seeded default accounts),
	// then release its store handles so a fresh manager can reopen the same
	// on-disk databases.
	w, err := NewManager().Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, w)
	require.NoError(t, w.closeRuntimeStore())

	// Act: a second create against the now fully created wallet.
	w2, err := NewManager().Create(cfg, params)

	// Assert: it is rejected as an existing wallet, not silently returned.
	require.ErrorIs(t, err, ErrWalletExists)
	require.Nil(t, w2)
}

// TestManagerCreateRetryCompletesUnseededWallet verifies the create-retry
// wedge fix (#1): a prior create that committed both the legacy wallet and the
// SQL runtime row but failed before seeding the default accounts must be
// completable by a retry. Because discardUnstarted only cleans in-memory state
// and never the durable rows, classifying such a wallet as fully created would
// permanently wedge it (ErrWalletExists with no usable accounts). The retry
// must instead replay the idempotent seeding and return the finished wallet.
func TestManagerCreateRetryCompletesUnseededWallet(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	runtimeExisted, err := createRuntimeWallet(
		context.Background(), cfg, params, rootKey,
		birthdayWithSafetyMargin(params.Birthday),
	)
	require.NoError(t, err)
	require.False(t, runtimeExisted)

	// Sanity check the seam: the default accounts are not yet present, so a
	// wedge-classifying create would reject this recoverable wallet.
	defaultName := waddrmgr.DefaultAccountName
	_, err = openSeededAccount(t, cfg, defaultName)
	require.ErrorIs(t, err, db.ErrAccountNotFound)

	// Act: retry the full create.
	w, err := NewManager().Create(cfg, params)

	// Assert: the retry completes the wallet rather than rejecting it, and
	// the default accounts the earlier attempt missed are now seeded.
	require.NoError(t, err)
	require.NotNil(t, w)
	t.Cleanup(func() {
		require.NoError(t, w.closeRuntimeStore())
	})

	for _, scope := range waddrmgr.DefaultKeyScopes {
		name := waddrmgr.DefaultAccountName
		info, err := w.store.GetAccount(t.Context(), db.GetAccountQuery{
			WalletID:    w.id,
			Scope:       db.KeyScope(scope),
			Name:        &name,
			SkipBalance: true,
		})
		require.NoError(t, err)
		require.Equal(t, waddrmgr.DefaultAccountName, info.AccountName)
	}
}

// openSeededAccount opens the SQL runtime store for cfg and reads the default
// account in the BIP0084 scope, used to probe whether default-account seeding
// has run.
func openSeededAccount(t *testing.T, cfg Config,
	name string) (*db.AccountInfo, error) {

	t.Helper()

	handle, err := openRuntimeStore(t.Context(), cfg, nil)
	require.NoError(t, err)

	info, accErr := handle.store.GetAccount(t.Context(), db.GetAccountQuery{
		WalletID:    handle.walletInfo.ID,
		Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
		Name:        &name,
		SkipBalance: true,
	})

	require.NoError(t, handle.close())

	return info, accErr
}

// TestManagerCreateRetryRejectsNilRootForSpendableRuntime verifies that a retry
// with no root key is rejected when the existing SQL wallet row is spendable.
func TestManagerCreateRetryRejectsNilRootForSpendableRuntime(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	spendableRoot, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)
	require.True(t, spendableRoot.IsPrivate())

	// Arrange: a partial create that committed the spendable SQL runtime row
	// but failed before post-load account seeding.
	_, err = createRuntimeWallet(
		context.Background(), cfg, params, spendableRoot,
		birthdayWithSafetyMargin(params.Birthday),
	)
	require.NoError(t, err)

	// Build a shell retry against the same name: shell mode derives no root
	// key, the nil-root case the fix guards.
	retryParams := CreateWalletParams{
		Mode:          ModeShell,
		PubPassphrase: params.PubPassphrase,
	}

	// Act: retry the create with no root key.
	w, err := NewManager().Create(cfg, retryParams)

	// Assert: the downgrade is rejected and the spendable SQL row was not
	// rebound to a rootless watch-only wallet.
	require.ErrorIs(t, err, ErrWalletParams)
	require.Nil(t, w)
}

// TestManagerCreateRetryPreservesRuntimeBirthday verifies that retrying a
// partial SQL create leaves the existing runtime birthday unchanged.
func TestManagerCreateRetryPreservesRuntimeBirthday(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	original := time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)
	params.Birthday = original

	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	// Arrange: a partial create that committed the SQL runtime row carrying the
	// original birthday, but failed before post-load account seeding.
	_, err = createRuntimeWallet(
		context.Background(), cfg, params, rootKey,
		birthdayWithSafetyMargin(params.Birthday),
	)
	require.NoError(t, err)

	// Build a retry that supplies a strictly later birthday, the regression
	// that would otherwise skip funds received before it.
	later := original.AddDate(2, 0, 0)
	require.True(t, later.After(original))

	retryParams := params
	retryParams.Birthday = later

	// Act: retry the full create with the later birthday.
	w, err := NewManager().Create(cfg, retryParams)
	require.NoError(t, err)
	require.NotNil(t, w)
	t.Cleanup(func() {
		require.NoError(t, w.closeRuntimeStore())
	})

	// Assert: the SQL runtime row kept the original birthday (with the
	// safety margin applied), not the later retry birthday.
	info, err := w.store.GetWallet(t.Context(), cfg.Name)
	require.NoError(t, err)
	require.True(t, info.Birthday.Equal(birthdayWithSafetyMargin(original)),
		"got %v want %v", info.Birthday,
		birthdayWithSafetyMargin(original))
	require.False(t, info.Birthday.Equal(birthdayWithSafetyMargin(later)))
}

// TestManagerCreateRetryRejectsSeedMismatch verifies that retrying a partial
// SQL create with a different seed is rejected rather than completing the
// wallet with default accounts derived from the wrong root key.
func TestManagerCreateRetryRejectsSeedMismatch(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	originalRoot, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	// Arrange: simulate a partial create by writing the SQL runtime row from
	// the original seed, without running post-load account seeding.
	_, err = createRuntimeWallet(
		context.Background(), cfg, params, originalRoot,
		birthdayWithSafetyMargin(params.Birthday),
	)
	require.NoError(t, err)

	// Build a retry that reuses the same name but supplies a different
	// seed, hence a different master key.
	mismatchedSeed, err := hdkeychain.GenerateSeed(
		hdkeychain.RecommendedSeedLen,
	)
	require.NoError(t, err)
	require.NotEqual(t, params.Seed, mismatchedSeed)

	retryParams := params
	retryParams.Seed = mismatchedSeed

	// Act: retry the full create with the mismatched seed.
	w, err := NewManager().Create(cfg, retryParams)

	// Assert: the mismatch is rejected and no SQL runtime row was created
	// from the wrong key material, so a correct retry can still proceed.
	require.ErrorIs(t, err, ErrWalletParams)
	require.Nil(t, w)

	w, err = NewManager().Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, w)
	t.Cleanup(func() {
		require.NoError(t, w.closeRuntimeStore())
	})
}
