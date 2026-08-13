//go:build itest

package itest

import (
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// testAccountManagerNewAccount verifies creating one derived account and
// rejecting a duplicate name in the same key scope.
func testAccountManagerNewAccount(h *bwtest.HarnessTest) {
	const (
		accountName    = "account manager new"
		contiguousName = "account manager after rejections"
		invalidName    = ""
		stoppedName    = "account manager stopped"
	)

	scope := waddrmgr.KeyScopeBIP0084
	ctx := h.Context()

	managed, _ := h.NewManagedWallet(bwtest.WalletFixture{Unlocked: true})
	w := managed.Wallet

	account, err := w.NewAccount(ctx, scope, accountName)
	require.NoError(h, err, "failed to create account")
	require.Equal(
		h, accountName, account.AccountName, "new account name mismatch",
	)
	require.Equal(
		h, scope, waddrmgr.KeyScope(account.KeyScope),
		"new account scope mismatch",
	)
	require.NotNil(
		h, account.AccountNumber, "derived account number is missing",
	)
	require.NotEmpty(
		h, account.PublicKey, "derived account public key is missing",
	)
	require.False(
		h, account.IsImported, "derived account is reported as imported",
	)
	wantKey := canonicalAccountKey(h, account.PublicKey)

	// A rejected duplicate must leave the account that owns the name exactly
	// as it was: re-derivation under the same name would silently replace a
	// key the caller may already have handed out addresses for. The public
	// ManagerError identity and the untouched row are both asserted.
	duplicate, err := w.NewAccount(ctx, scope, accountName)
	require.Error(h, err, "duplicate account name was accepted")
	require.True(
		h, waddrmgr.IsError(err, waddrmgr.ErrDuplicateAccount),
		"duplicate account error has wrong public identity",
	)
	require.Nil(h, duplicate, "duplicate account returned account info")

	duplicatePostcondition, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "failed to check duplicate postcondition")
	require.Equal(h, accountName, duplicatePostcondition.AccountName)
	require.Equal(
		h, scope, waddrmgr.KeyScope(duplicatePostcondition.KeyScope),
	)
	require.Equal(
		h, account.AccountNumber, duplicatePostcondition.AccountNumber,
	)
	require.Equal(
		h, wantKey, canonicalAccountKey(h, duplicatePostcondition.PublicKey),
	)
	require.False(h, duplicatePostcondition.IsImported)

	// An empty name is rejected by name validation before an account number is
	// allocated, so nothing may become queryable under it.
	invalid, err := w.NewAccount(ctx, scope, invalidName)
	require.Error(h, err, "empty account name was accepted")
	require.Nil(h, invalid, "invalid account returned account info")

	invalidPostcondition, err := w.GetAccount(ctx, scope, invalidName)
	require.Error(h, err, "empty account name resolved after rejection")
	require.Nil(h, invalidPostcondition)

	// Deriving m/purpose'/coin'/account' needs the master HD private key, which
	// only an unlocked wallet holds, and a stopped wallet admits no operation
	// at all. Both gates must reject before the account number is consumed.
	require.NoError(h, w.Lock(ctx), "failed to lock wallet")
	locked, err := w.NewAccount(ctx, scope, "account manager locked")
	require.Error(h, err, "locked wallet accepted a new account")
	require.Nil(h, locked, "locked wallet returned account info")
	h.UnlockWallet(w)
	_, err = w.GetAccount(ctx, scope, "account manager locked")
	require.Error(h, err, "locked account was persisted after rejection")

	require.NoError(h, w.Stop(ctx), "failed to stop wallet")
	stopped, err := w.NewAccount(ctx, scope, stoppedName)
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"stopped wallet accepted a new account",
	)
	require.Nil(h, stopped, "stopped wallet returned account info")

	// Reopening the wallet and its Manager reads the account back out of the
	// store, so what survives below is committed state rather than something
	// the first wallet happened to still hold in memory. The whole published
	// view is compared, since a reload must not alter any of it.
	managed = h.ReloadWallet(managed)
	reloaded := managed.Wallet
	durable, err := reloaded.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "failed to load durable account")
	require.Equal(
		h, duplicatePostcondition, durable, "reload changed the account view",
	)

	_, err = reloaded.GetAccount(ctx, scope, stoppedName)
	require.Error(h, err, "stopped account was persisted after rejection")

	// A second handoff proves the returned bundle carries fresh handles and
	// leaves only its wallet under harness teardown ownership.
	firstReload := reloaded
	managed = h.ReloadWallet(managed)
	reloaded = managed.Wallet
	require.NotSame(h, firstReload, reloaded)
	active := h.ActiveWallets()
	require.Len(h, active, 1)
	require.Same(h, reloaded, active[0])

	// A successful creation after every rejection must receive the immediate
	// next BIP44 account number, proving no rejected call advanced the
	// allocator.
	h.UnlockWallet(reloaded)
	contiguous, err := reloaded.NewAccount(ctx, scope, contiguousName)
	require.NoError(h, err, "failed to create account after rejections")
	require.NotNil(
		h, contiguous.AccountNumber,
		"account after rejections has no account number",
	)
	require.Equal(
		h, *account.AccountNumber+1, *contiguous.AccountNumber,
		"rejected calls consumed an account number",
	)
}

// testAccountManagerNewAccountWatchOnly verifies that a watch-only wallet
// rejects deriving a new account.
//
// NewAccount is still the subject here, so this belongs with the case above.
// It is registered separately because the subject wallet must be watch-only
// for the whole test, and kvdb serves a single wallet per database: keeping
// both cases in one registered test would mean either a second database or a
// backend-conditional fixture. The wallet is rootless, the one watch-only
// shape every backend can represent.
func testAccountManagerNewAccountWatchOnly(h *bwtest.HarnessTest) {
	const accountName = "account manager watch only"

	scope := waddrmgr.KeyScopeBIP0084
	ctx := h.Context()

	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})
	require.True(h, w.IsWatchOnly(), "watch-only fixture is not watch-only")

	// A watch-only wallet holds no master HD private key, so it cannot derive
	// the account key; its keyspace arrives through ImportAccount instead. The
	// assertion stays at the public outcome: the call fails and no account
	// exists under the requested name.
	account, err := w.NewAccount(ctx, scope, accountName)
	require.Error(h, err, "watch-only wallet accepted a new account")
	require.Nil(h, account, "watch-only rejection returned account info")

	_, err = w.GetAccount(ctx, scope, accountName)
	require.Error(h, err, "watch-only account was persisted after rejection")
}
