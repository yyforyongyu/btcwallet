//go:build itest

package itest

import (
	"bytes"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// testAccountManagerImportAccount verifies one account xpub import through the
// public AccountManager API, including rename, rollback, and durable reload.
func testAccountManagerImportAccount(h *bwtest.HarnessTest) {
	const (
		accountName = "account manager imported"
		renamedName = "account manager imported renamed"
		dryRunName  = "account manager dry run"
		invalidName = ""
	)

	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	addrType := waddrmgr.WitnessPubKey

	// Prepare two deterministic private account keys, then neuter them for
	// watch-only use. One is imported while the other seeds the wallet and
	// exercises the dry-run and duplicate-name paths.
	seed := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	root, err := hdkeychain.NewMaster(seed, h.NetParams())
	require.NoError(h, err, "failed to derive deterministic root")
	purpose, err := root.Derive(
		hdkeychain.HardenedKeyStart + scope.Purpose,
	)
	require.NoError(h, err, "failed to derive BIP84 purpose key")

	fingerprint := purpose.ParentFingerprint()
	coinType, err := purpose.Derive(
		hdkeychain.HardenedKeyStart + h.NetParams().HDCoinType,
	)
	require.NoError(h, err, "failed to derive BIP84 coin-type key")
	accountPrivate, err := coinType.Derive(
		hdkeychain.HardenedKeyStart,
	)
	require.NoError(h, err, "failed to derive account private key")
	accountKey, err := accountPrivate.Neuter()
	require.NoError(h, err, "failed to derive account public key")
	otherPrivate, err := coinType.Derive(
		hdkeychain.HardenedKeyStart + 1,
	)
	require.NoError(h, err, "failed to derive second account private key")
	otherKey, err := otherPrivate.Neuter()
	require.NoError(h, err, "failed to derive second account public key")
	require.NotEqual(h, accountKey.String(), otherKey.String())
	publicKey := bytes.Clone([]byte(accountKey.String()))

	managed, _ := h.NewManagedWallet(bwtest.WalletFixture{
		InitialAccounts: []wallet.WatchOnlyAccount{{
			Scope:                scope,
			XPub:                 otherKey,
			MasterKeyFingerprint: fingerprint,
			Name:                 "account manager watch-only seed",
			AddrType:             addrType,
		}},
	})
	w := managed.Wallet
	require.True(h, w.IsWatchOnly(), "watch-only fixture is not watch-only")
	seeded, err := w.GetAccount(
		ctx, scope, "account manager watch-only seed",
	)
	require.NoError(h, err, "failed to read seeded watch-only account")
	require.Equal(h, []byte(otherKey.String()), seeded.PublicKey)

	// A dry run returns a preview without persisting an account row.
	dryRun, err := w.ImportAccount(
		ctx, dryRunName, otherKey, fingerprint, addrType, true,
	)
	require.NoError(h, err, "failed to dry-run account import")
	require.Equal(h, dryRunName, dryRun.AccountName)
	require.Equal(h, scope, waddrmgr.KeyScope(dryRun.KeyScope))
	require.True(h, dryRun.IsImported)
	require.True(h, dryRun.IsWatchOnly)
	require.Nil(h, dryRun.AccountNumber)
	require.Equal(h, []byte(otherKey.String()), dryRun.PublicKey)
	require.Equal(h, fingerprint, dryRun.MasterKeyFingerprint)

	_, err = w.GetAccount(ctx, scope, dryRunName)
	require.Error(h, err, "dry-run account was persisted")

	// The same public method persists the exact caller-supplied identity.
	imported, err := w.ImportAccount(
		ctx, accountName, accountKey, fingerprint, addrType, false,
	)
	require.NoError(h, err, "failed to import account")
	require.Equal(h, accountName, imported.AccountName)
	require.Equal(h, scope, waddrmgr.KeyScope(imported.KeyScope))
	require.True(h, imported.IsImported)
	require.True(h, imported.IsWatchOnly)
	require.Nil(h, imported.AccountNumber)
	require.Zero(h, imported.ExternalKeyCount)
	require.Zero(h, imported.InternalKeyCount)
	require.Zero(h, imported.ImportedKeyCount)
	require.Zero(h, imported.ConfirmedBalance)
	require.Zero(h, imported.UnconfirmedBalance)
	require.NotZero(h, imported.CreatedAt)
	require.Equal(h, publicKey, imported.PublicKey)
	require.Equal(h, fingerprint, imported.MasterKeyFingerprint)

	externalAddr, err := w.NewAddress(ctx, accountName, addrType, false)
	require.NoError(h, err, "failed to derive imported external address")
	externalScript, err := txscript.PayToAddrScript(externalAddr)
	require.NoError(h, err, "failed to create imported external pkscript")
	require.True(h, txscript.IsPayToWitnessPubKeyHash(externalScript))

	internalAddr, err := w.NewAddress(ctx, accountName, addrType, true)
	require.NoError(h, err, "failed to derive imported internal address")
	internalScript, err := txscript.PayToAddrScript(internalAddr)
	require.NoError(h, err, "failed to create imported internal pkscript")
	require.True(h, txscript.IsPayToWitnessPubKeyHash(internalScript))

	// An exact duplicate request and a duplicate name must not replace a row.
	duplicate, err := w.ImportAccount(
		ctx, accountName, accountKey, fingerprint, addrType, false,
	)
	require.Error(h, err, "exact duplicate request was accepted")
	require.Nil(h, duplicate)

	existing, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "original imported account was lost")
	require.Equal(h, publicKey, existing.PublicKey)
	require.Equal(h, fingerprint, existing.MasterKeyFingerprint)
	require.Equal(h, uint32(1), existing.ExternalKeyCount)
	require.Equal(h, uint32(1), existing.InternalKeyCount)

	duplicate, err = w.ImportAccount(
		ctx, accountName, otherKey, fingerprint, addrType, false,
	)
	require.Error(h, err, "duplicate account name was accepted")
	require.Nil(h, duplicate)

	existing, err = w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "duplicate name removed original account")
	require.Equal(h, publicKey, existing.PublicKey)

	// Invalid names and keys are rejected before an account row is created.
	// Empty-name validation uses an internal store sentinel, so the test
	// asserts only the public failure and absence of a persisted account.
	invalid, err := w.ImportAccount(
		ctx, invalidName, otherKey, fingerprint, addrType, false,
	)
	require.Error(h, err, "empty account name was accepted")
	require.Nil(h, invalid)

	_, err = w.GetAccount(ctx, scope, invalidName)
	require.Error(h, err, "invalid-name import left a row")
	invalid, err = w.ImportAccount(
		ctx, "account manager invalid nil", nil, fingerprint, addrType, false,
	)
	require.ErrorIs(h, err, wallet.ErrInvalidAccountKey)
	require.Nil(h, invalid)

	_, err = w.GetAccount(ctx, scope, "account manager invalid nil")
	require.Error(h, err, "nil-key import left a row")
	invalid, err = w.ImportAccount(
		ctx, "account manager invalid private", accountPrivate,
		fingerprint, addrType, false,
	)
	require.ErrorIs(h, err, wallet.ErrInvalidAccountKey)
	require.Nil(h, invalid)

	_, err = w.GetAccount(ctx, scope, "account manager invalid private")
	require.Error(h, err, "private-key import left a row")

	expectedRenamed := *existing
	expectedRenamed.AccountName = renamedName
	err = w.RenameAccount(ctx, scope, accountName, renamedName)
	require.NoError(h, err, "failed to rename imported account")

	_, err = w.GetAccount(ctx, scope, accountName)
	require.Error(h, err, "old imported account name still resolves")

	renamed, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "failed to read renamed imported account")
	require.Equal(h, expectedRenamed, *renamed)

	// ImportAccount is admitted while started and rejects only after Stop.
	require.NoError(h, w.Stop(ctx), "failed to stop wallet")
	invalid, err = w.ImportAccount(
		ctx, "account manager stopped", otherKey, fingerprint, addrType, false,
	)
	require.ErrorIs(h, err, wallet.ErrStateForbidden)
	require.Nil(h, invalid)

	// Reopening proves the import was committed rather than held in memory by
	// the first wallet. The whole published view is compared, since a reload
	// must not alter any part of it.
	managed = h.ReloadWallet(managed)
	reloaded := managed.Wallet
	durable, err := reloaded.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "failed to reload imported account")
	require.Equal(
		h, renamed, durable, "reload changed the renamed imported account view",
	)

	_, err = reloaded.GetAccount(ctx, scope, accountName)
	require.Error(h, err, "old imported account name was restored on reload")

	_, err = reloaded.GetAccount(ctx, scope, "account manager stopped")
	require.Error(h, err, "stopped import was persisted")
}
