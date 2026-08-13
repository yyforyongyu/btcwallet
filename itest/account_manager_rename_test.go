//go:build itest

package itest

import (
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// testAccountManagerRenameAccount verifies derived-account identity, rejection
// atomicity, lifecycle admission, and durable persistence for RenameAccount.
func testAccountManagerRenameAccount(h *bwtest.HarnessTest) {
	const (
		sourceName     = "account manager rename source"
		targetName     = "account manager rename target"
		renamedName    = "account manager renamed"
		unknownSource  = "account manager unknown source"
		unknownTarget  = "account manager unknown target"
		reservedTarget = "account manager reserved source target"
		lockedTarget   = "account manager locked target"
		stoppedTarget  = "account manager stopped target"
	)

	scope := waddrmgr.KeyScopeBIP0084
	ctx := h.Context()

	managed, _ := h.NewManagedWallet(bwtest.WalletFixture{Unlocked: true})
	w := managed.Wallet

	// A second account is needed so the collision case below has a name that is
	// really taken; renaming into an unused name would pass vacuously.
	source, err := w.NewAccount(ctx, scope, sourceName)
	require.NoError(h, err, "failed to create rename source account")
	require.NotNil(h, source.AccountNumber)
	require.NotEmpty(h, source.PublicKey)
	require.False(h, source.IsImported)
	wantSourceKey := canonicalAccountKey(h, source.PublicKey)

	target, err := w.NewAccount(ctx, scope, targetName)
	require.NoError(h, err, "failed to create duplicate target account")
	require.NotNil(h, target.AccountNumber)
	require.NotEmpty(h, target.PublicKey)
	require.False(h, target.IsImported)
	wantTargetKey := canonicalAccountKey(h, target.PublicKey)

	// A rename moves the name only. The account number and derived key identify
	// the keyspace the caller already holds addresses for, so both must survive
	// unchanged, and the old name must stop resolving.
	err = w.RenameAccount(ctx, scope, sourceName, renamedName)
	require.NoError(h, err, "failed to rename derived account")
	renamed, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "failed to read renamed account")
	require.Equal(h, renamedName, renamed.AccountName)
	require.Equal(h, scope, waddrmgr.KeyScope(renamed.KeyScope))
	require.Equal(h, source.AccountNumber, renamed.AccountNumber)
	require.Equal(h, wantSourceKey, canonicalAccountKey(h, renamed.PublicKey))
	require.False(h, renamed.IsImported)

	_, err = w.GetAccount(ctx, scope, sourceName)
	require.Error(h, err, "old account name still resolves after rename")

	// A duplicate target name must leave both accounts unchanged. Both account
	// views are read back to prove neither identity moved.
	err = w.RenameAccount(ctx, scope, renamedName, targetName)
	require.Error(h, err, "duplicate target name was accepted")
	sourceAfterDuplicate, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "failed to read source after duplicate rejection")
	require.Equal(h, renamedName, sourceAfterDuplicate.AccountName)
	require.Equal(h, source.AccountNumber, sourceAfterDuplicate.AccountNumber)
	require.Equal(
		h, wantSourceKey,
		canonicalAccountKey(h, sourceAfterDuplicate.PublicKey),
	)
	require.False(h, sourceAfterDuplicate.IsImported)

	targetAfterDuplicate, err := w.GetAccount(ctx, scope, targetName)
	require.NoError(h, err, "failed to read target after duplicate rejection")
	require.Equal(h, targetName, targetAfterDuplicate.AccountName)
	require.Equal(h, target.AccountNumber, targetAfterDuplicate.AccountNumber)
	require.Equal(
		h, wantTargetKey,
		canonicalAccountKey(h, targetAfterDuplicate.PublicKey),
	)
	require.False(h, targetAfterDuplicate.IsImported)

	// An empty target name must fail validation without modifying the source
	// account or creating an account under the invalid name.
	err = w.RenameAccount(ctx, scope, renamedName, "")
	require.Error(h, err, "empty target name was accepted")
	invalidPostcondition, err := w.GetAccount(ctx, scope, "")
	require.Error(h, err, "empty target name resolved after rejection")
	require.Nil(h, invalidPostcondition)

	sourceAfterInvalid, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(
		h, err, "failed to read source after invalid-name rejection",
	)
	require.Equal(h, renamedName, sourceAfterInvalid.AccountName)
	require.Equal(h, source.AccountNumber, sourceAfterInvalid.AccountNumber)
	require.Equal(
		h, wantSourceKey,
		canonicalAccountKey(h, sourceAfterInvalid.PublicKey),
	)
	require.False(h, sourceAfterInvalid.IsImported)

	// Renaming a name nobody holds must fail rather than create the target,
	// which an upsert-shaped implementation would do.
	err = w.RenameAccount(ctx, scope, unknownSource, unknownTarget)
	require.Error(h, err, "unknown source was accepted")
	unknownPostcondition, err := w.GetAccount(ctx, scope, unknownTarget)
	require.Error(h, err, "unknown target resolved after rejection")
	require.Nil(h, unknownPostcondition)

	sourceAfterUnknown, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(
		h, err, "failed to read source after unknown-source rejection",
	)
	require.Equal(h, renamedName, sourceAfterUnknown.AccountName)
	require.Equal(h, source.AccountNumber, sourceAfterUnknown.AccountNumber)
	require.Equal(
		h, wantSourceKey,
		canonicalAccountKey(h, sourceAfterUnknown.PublicKey),
	)
	require.False(h, sourceAfterUnknown.IsImported)

	// The imported alias is a legacy pseudo-account on kvdb and absent on SQL.
	// Snapshot either representation so both reserved-name rejection paths can
	// prove that they leave the alias unchanged without branching on a backend.
	importedBefore, importedBeforeErr := w.GetAccount(
		ctx, scope, waddrmgr.ImportedAddrAccountName,
	)
	importedExists := importedBeforeErr == nil

	// A derived account cannot take the reserved imported alias. Validation
	// must reject before either the derived source or imported target changes.
	err = w.RenameAccount(
		ctx, scope, renamedName, waddrmgr.ImportedAddrAccountName,
	)
	require.True(h, waddrmgr.IsError(err, waddrmgr.ErrInvalidAccount))
	sourceAfterReservedTarget, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "failed to read source after reserved target")
	require.Equal(h, sourceAfterUnknown, sourceAfterReservedTarget)

	importedAfterReservedTarget, importedAfterReservedTargetErr := w.GetAccount(
		ctx, scope, waddrmgr.ImportedAddrAccountName,
	)
	require.Equal(
		h, importedExists, importedAfterReservedTargetErr == nil,
		"reserved imported account existence changed",
	)
	require.Equal(
		h, importedBefore, importedAfterReservedTarget,
		"reserved imported account state changed",
	)

	// The reserved imported alias cannot be renamed. The source alias must
	// remain unchanged and the requested target must not become queryable.
	err = w.RenameAccount(
		ctx, scope, waddrmgr.ImportedAddrAccountName, reservedTarget,
	)
	require.ErrorIs(h, err, wallet.ErrAccountNotFound)
	sourceAfterReservedSource, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "failed to read source after reserved source")
	require.Equal(h, sourceAfterReservedTarget, sourceAfterReservedSource)

	reservedPostcondition, err := w.GetAccount(ctx, scope, reservedTarget)
	require.Error(h, err, "reserved source rename created the target")
	require.Nil(h, reservedPostcondition)

	importedAfterReservedSource, importedAfterReservedSourceErr := w.GetAccount(
		ctx, scope, waddrmgr.ImportedAddrAccountName,
	)
	require.Equal(
		h, importedExists, importedAfterReservedSourceErr == nil,
		"reserved imported account existence changed",
	)
	require.Equal(
		h, importedBefore, importedAfterReservedSource,
		"reserved imported account state changed",
	)

	// A rename only rewrites metadata, so unlike NewAccount it needs no key
	// material and the maintained contract admits it on a locked wallet. The
	// gate that applies is the started-state one, checked after Stop below.
	require.NoError(h, w.Lock(ctx), "failed to lock wallet")
	err = w.RenameAccount(ctx, scope, renamedName, lockedTarget)
	require.NoError(h, err, "locked wallet rejected a metadata rename")
	lockedSource, err := w.GetAccount(ctx, scope, lockedTarget)
	require.NoError(h, err, "failed to read locked-wallet rename")
	require.Equal(h, lockedTarget, lockedSource.AccountName)
	require.Equal(h, source.AccountNumber, lockedSource.AccountNumber)
	require.Equal(
		h, wantSourceKey, canonicalAccountKey(h, lockedSource.PublicKey),
	)
	require.False(h, lockedSource.IsImported)

	_, err = w.GetAccount(ctx, scope, renamedName)
	require.Error(h, err, "pre-lock account name still resolves")
	h.UnlockWallet(w)

	// A stopped wallet admits no mutation, and this gate does have an exported
	// sentinel, so it is asserted by identity rather than by message.
	require.NoError(h, w.Stop(ctx), "failed to stop wallet")
	err = w.RenameAccount(ctx, scope, lockedTarget, stoppedTarget)
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden, "stopped wallet accepted a rename",
	)

	// Reopening from the store proves the accepted rename was committed and
	// every rejected one wrote nothing, rather than both being in-memory state.
	// Both accounts are compared as whole published views, since a reload must
	// not alter any part of them.
	managed = h.ReloadWallet(managed)
	reloaded := managed.Wallet
	durable, err := reloaded.GetAccount(ctx, scope, lockedTarget)
	require.NoError(h, err, "failed to read renamed account after reload")
	require.Equal(
		h, lockedSource, durable, "reload changed the renamed account view",
	)

	durableTarget, err := reloaded.GetAccount(ctx, scope, targetName)
	require.NoError(h, err, "failed to read duplicate target after reload")
	require.Equal(
		h, targetAfterDuplicate, durableTarget,
		"reload changed the rename target's account view",
	)

	for _, absentName := range []string{
		sourceName, renamedName, "", unknownTarget, reservedTarget,
		stoppedTarget,
	} {
		_, err = reloaded.GetAccount(ctx, scope, absentName)
		require.Error(h, err, "rejected rename target or old name persisted")
	}
}
