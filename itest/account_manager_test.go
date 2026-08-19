//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// assertAccountInfoEqual compares every exported semantic AccountInfo field.
// Keeping this comparison explicit makes additions to the public DTO visible
// to the integration-test compiler and reviewer.
func assertAccountInfoEqual(h *bwtest.HarnessTest, want,
	got *wallet.AccountInfo) {

	h.Helper()

	require.Equal(h, want.AccountNumber, got.AccountNumber)
	require.Equal(h, want.AccountName, got.AccountName)
	require.Equal(h, want.IsImported, got.IsImported)
	require.Equal(h, want.ExternalKeyCount, got.ExternalKeyCount)
	require.Equal(h, want.InternalKeyCount, got.InternalKeyCount)
	require.Equal(h, want.ImportedKeyCount, got.ImportedKeyCount)
	require.Equal(h, want.ConfirmedBalance, got.ConfirmedBalance)
	require.Equal(h, want.UnconfirmedBalance, got.UnconfirmedBalance)
	require.Equal(h, want.IsWatchOnly, got.IsWatchOnly)
	require.Equal(h, want.CreatedAt, got.CreatedAt)
	require.Equal(h, want.KeyScope, got.KeyScope)
	require.Equal(h, want.AddrSchema, got.AddrSchema)
	require.Equal(h, want.PublicKey, got.PublicKey)
	require.Equal(
		h, want.MasterKeyFingerprint, got.MasterKeyFingerprint,
	)
}

// assertNewDerivedAccountInfoShape verifies the complete public shape returned
// by a successful root-derived account creation without asserting an exact
// account number owned by a later task.
func assertNewDerivedAccountInfoShape(h *bwtest.HarnessTest, name string,
	scope waddrmgr.KeyScope, got *wallet.AccountInfo) {

	h.Helper()

	wantSchema, ok := waddrmgr.ScopeAddrMap[scope]
	require.True(h, ok, "missing address schema for scope")

	require.NotNil(h, got.AccountNumber)
	require.Equal(h, name, got.AccountName)
	require.False(h, got.IsImported)
	require.Zero(h, got.ExternalKeyCount)
	require.Zero(h, got.InternalKeyCount)
	require.Zero(h, got.ImportedKeyCount)
	require.Zero(h, got.ConfirmedBalance)
	require.Zero(h, got.UnconfirmedBalance)
	require.False(h, got.IsWatchOnly)
	require.NotZero(h, got.CreatedAt)
	require.Equal(h, scope, got.KeyScope)
	require.Equal(h, wantSchema, got.AddrSchema)
	require.NotEmpty(h, got.PublicKey)
	require.NotNil(h, got.MasterKeyFingerprint)
	require.NotZero(h, *got.MasterKeyFingerprint)
}

// assertImportedAccountInfoShape verifies the complete public shape returned
// by an imported account mutation or preview.
func assertImportedAccountInfoShape(h *bwtest.HarnessTest, name string,
	accountKey *hdkeychain.ExtendedKey, fingerprint uint32,
	addrType waddrmgr.AddressType, got *wallet.AccountInfo) {

	h.Helper()

	wantFingerprint := wallet.MasterFingerprint(fingerprint)
	wantSchema := waddrmgr.ScopeAddrSchema{
		ExternalAddrType: addrType,
		InternalAddrType: addrType,
	}

	require.Nil(h, got.AccountNumber)
	require.Equal(h, name, got.AccountName)
	require.True(h, got.IsImported)
	require.Zero(h, got.ExternalKeyCount)
	require.Zero(h, got.InternalKeyCount)
	require.Zero(h, got.ImportedKeyCount)
	require.Zero(h, got.ConfirmedBalance)
	require.Zero(h, got.UnconfirmedBalance)
	require.True(h, got.IsWatchOnly)
	require.NotZero(h, got.CreatedAt)
	require.Equal(h, waddrmgr.KeyScopeBIP0084, got.KeyScope)
	require.Equal(h, wantSchema, got.AddrSchema)
	require.Equal(h, []byte(accountKey.String()), got.PublicKey)
	require.Equal(h, &wantFingerprint, got.MasterKeyFingerprint)
}

// importedAccountFixture derives deterministic BIP84 account public material
// for an import test without persisting any wallet state.
func importedAccountFixture(h *bwtest.HarnessTest,
	account uint32) (*hdkeychain.ExtendedKey, *hdkeychain.ExtendedKey, uint32) {

	h.Helper()

	seed := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	root, err := hdkeychain.NewMaster(seed, h.NetParams())
	require.NoError(h, err, "derive deterministic root")
	purpose, err := root.Derive(
		hdkeychain.HardenedKeyStart + waddrmgr.KeyScopeBIP0084.Purpose,
	)
	require.NoError(h, err, "derive BIP84 purpose key")
	coinType, err := purpose.Derive(
		hdkeychain.HardenedKeyStart + h.NetParams().HDCoinType,
	)
	require.NoError(h, err, "derive BIP84 coin-type key")
	privateKey, err := coinType.Derive(
		hdkeychain.HardenedKeyStart + account,
	)
	require.NoError(h, err, "derive account private key")
	publicKey, err := privateKey.Neuter()
	require.NoError(h, err, "neuter account key")

	return privateKey, publicKey, purpose.ParentFingerprint()
}

// testAccountManagerCreateAccount verifies one successful NewAccount mutation
// and its immediate durable postcondition.
func testAccountManagerCreateAccount(h *bwtest.HarnessTest) {
	const accountName = "account manager created"

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})

	// Act.
	created, err := w.NewAccount(ctx, scope, accountName)

	// Assert.
	require.NoError(h, err, "create account")
	assertNewDerivedAccountInfoShape(h, accountName, scope, created)

	queried, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "query created account")
	assertAccountInfoEqual(h, created, queried)

	w = h.ReloadWallet(w)
	durable, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "query reloaded account")
	assertAccountInfoEqual(h, created, durable)
}

// testAccountManagerRejectDuplicateAccountCreation verifies a duplicate name
// cannot replace the account that already owns it.
func testAccountManagerRejectDuplicateAccountCreation(h *bwtest.HarnessTest) {
	const accountName = "account manager duplicate"

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	existing, err := w.NewAccount(ctx, scope, accountName)
	require.NoError(h, err, "arrange existing account")

	// Act.
	duplicate, err := w.NewAccount(ctx, scope, accountName)

	// Assert.
	var managerErr waddrmgr.ManagerError
	require.ErrorAs(h, err, &managerErr)
	require.Equal(h, waddrmgr.ErrDuplicateAccount, managerErr.ErrorCode)
	require.Nil(h, duplicate)

	unchanged, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "query account after duplicate rejection")
	assertAccountInfoEqual(h, existing, unchanged)
}

// testAccountManagerRejectInvalidAccountCreation verifies name validation
// leaves no account behind.
func testAccountManagerRejectInvalidAccountCreation(h *bwtest.HarnessTest) {
	const invalidName = ""

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})

	// Act.
	created, err := w.NewAccount(ctx, scope, invalidName)

	// Assert.
	require.Error(h, err)
	require.Nil(h, created)
	missing, err := w.GetAccount(ctx, scope, invalidName)
	require.Error(h, err)
	require.Nil(h, missing)
}

// testAccountManagerRejectLockedAccountCreation verifies NewAccount cannot
// derive account key material while the wallet is locked.
func testAccountManagerRejectLockedAccountCreation(h *bwtest.HarnessTest) {
	const accountName = "account manager locked"

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{})

	// Act.
	created, err := w.NewAccount(ctx, scope, accountName)

	// Assert.
	require.Error(h, err)
	require.Nil(h, created)
	missing, err := w.GetAccount(ctx, scope, accountName)
	require.Error(h, err)
	require.Nil(h, missing)
}

// testAccountManagerRejectWatchOnlyAccountCreation verifies a rootless wallet
// cannot derive a new account from private root material it does not own.
func testAccountManagerRejectWatchOnlyAccountCreation(h *bwtest.HarnessTest) {
	const accountName = "account manager watchonly"

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})

	// Act.
	created, err := w.NewAccount(ctx, scope, accountName)

	// Assert.
	require.Error(h, err)
	require.Nil(h, created)
	missing, err := w.GetAccount(ctx, scope, accountName)
	require.Error(h, err)
	require.Nil(h, missing)
}

// testAccountManagerRejectStoppedAccountCreation verifies a stopped wallet
// rejects NewAccount before persisting a row.
func testAccountManagerRejectStoppedAccountCreation(h *bwtest.HarnessTest) {
	const accountName = "account manager stopped"

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	require.NoError(h, w.Stop(ctx), "stop wallet")

	// Act.
	created, err := w.NewAccount(ctx, scope, accountName)

	// Assert.
	require.ErrorIs(h, err, wallet.ErrStateForbidden)
	require.Nil(h, created)

	w = h.ReloadWallet(w)
	missing, err := w.GetAccount(ctx, scope, accountName)
	require.Error(h, err)
	require.Nil(h, missing)
}

// testAccountManagerRenameDerivedAccount verifies RenameAccount changes only
// the name of account zero and persists that change across reload.
func testAccountManagerRenameDerivedAccount(h *bwtest.HarnessTest) {
	const (
		sourceName  = "account manager rename source"
		renamedName = "account manager renamed derived"
	)

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	_, err := w.NewAccount(ctx, scope, sourceName)
	require.NoError(h, err, "arrange rename source")
	before, err := w.GetAccount(ctx, scope, sourceName)
	require.NoError(h, err, "query rename source")
	want := *before
	want.AccountName = renamedName

	// Act.
	err = w.RenameAccount(ctx, scope, sourceName, renamedName)

	// Assert.
	require.NoError(h, err, "rename derived account")
	renamed, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "query renamed account")
	assertAccountInfoEqual(h, &want, renamed)
	old, err := w.GetAccount(ctx, scope, sourceName)
	require.Error(h, err)
	require.Nil(h, old)

	w = h.ReloadWallet(w)
	durable, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "query reloaded renamed account")
	assertAccountInfoEqual(h, &want, durable)
}

// testAccountManagerRenameImportedAccount verifies an imported XPub account
// can be renamed through the same public contract on every backend.
func testAccountManagerRenameImportedAccount(h *bwtest.HarnessTest) {
	const (
		accountName = "account manager imported source"
		renamedName = "account manager imported target"
	)

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	_, accountKey, fingerprint := importedAccountFixture(h, 0)
	w, _ := h.NewWallet(bwtest.WalletFixture{
		InitialAccounts: []wallet.WatchOnlyAccount{{
			Scope:                scope,
			XPub:                 accountKey,
			MasterKeyFingerprint: fingerprint,
			Name:                 accountName,
			AddrType:             waddrmgr.WitnessPubKey,
		}},
	})
	before, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "query imported account")
	want := *before
	want.AccountName = renamedName

	// Act.
	err = w.RenameAccount(ctx, scope, accountName, renamedName)

	// Assert.
	require.NoError(h, err, "rename imported account")
	renamed, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "query renamed imported account")
	assertAccountInfoEqual(h, &want, renamed)
	old, err := w.GetAccount(ctx, scope, accountName)
	require.Error(h, err)
	require.Nil(h, old)

	w = h.ReloadWallet(w)
	durable, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "query reloaded imported account")
	assertAccountInfoEqual(h, &want, durable)
}

// testAccountManagerRejectDuplicateAccountRename verifies a taken target name
// leaves both the source and target account unchanged.
func testAccountManagerRejectDuplicateAccountRename(h *bwtest.HarnessTest) {
	const (
		sourceName = "account manager duplicate rename source"
		targetName = "account manager rename collision"
	)

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	_, err := w.NewAccount(ctx, scope, sourceName)
	require.NoError(h, err, "arrange rename source")
	sourceBefore, err := w.GetAccount(ctx, scope, sourceName)
	require.NoError(h, err, "query rename source")
	_, err = w.NewAccount(ctx, scope, targetName)
	require.NoError(h, err, "arrange occupied target")
	targetBefore, err := w.GetAccount(ctx, scope, targetName)
	require.NoError(h, err, "query rename target")

	// Act.
	err = w.RenameAccount(ctx, scope, sourceName, targetName)

	// Assert.
	require.Error(h, err)
	sourceAfter, err := w.GetAccount(ctx, scope, sourceName)
	require.NoError(h, err, "query source after rejected rename")
	assertAccountInfoEqual(h, sourceBefore, sourceAfter)
	targetAfter, err := w.GetAccount(ctx, scope, targetName)
	require.NoError(h, err, "query target after rejected rename")
	assertAccountInfoEqual(h, targetBefore, targetAfter)
}

// testAccountManagerRejectInvalidAccountRename verifies invalid target names
// leave the source account unchanged and create no target.
func testAccountManagerRejectInvalidAccountRename(h *bwtest.HarnessTest) {
	const (
		sourceName  = "account manager invalid rename source"
		invalidName = ""
	)

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	_, err := w.NewAccount(ctx, scope, sourceName)
	require.NoError(h, err, "arrange rename source")
	sourceBefore, err := w.GetAccount(ctx, scope, sourceName)
	require.NoError(h, err, "query rename source")

	// Act.
	err = w.RenameAccount(ctx, scope, sourceName, invalidName)

	// Assert.
	var managerErr waddrmgr.ManagerError
	require.ErrorAs(h, err, &managerErr)
	require.Equal(h, waddrmgr.ErrInvalidAccount, managerErr.ErrorCode)
	sourceAfter, err := w.GetAccount(ctx, scope, sourceName)
	require.NoError(h, err, "query source after invalid rename")
	assertAccountInfoEqual(h, sourceBefore, sourceAfter)
	invalid, err := w.GetAccount(ctx, scope, invalidName)
	require.Error(h, err)
	require.Nil(h, invalid)
}

// testAccountManagerRejectUnknownAccountRename verifies RenameAccount cannot
// create a target when its source account does not exist.
func testAccountManagerRejectUnknownAccountRename(h *bwtest.HarnessTest) {
	const (
		unknownName = "account manager unknown source"
		targetName  = "account manager unknown target"
	)

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{})

	// Act.
	err := w.RenameAccount(ctx, scope, unknownName, targetName)

	// Assert.
	require.ErrorIs(h, err, wallet.ErrAccountNotFound)
	target, err := w.GetAccount(ctx, scope, targetName)
	require.Error(h, err)
	require.Nil(h, target)
}

// testAccountManagerRenameLockedAccount verifies metadata-only renames remain
// admitted while the wallet key vault is locked.
func testAccountManagerRenameLockedAccount(h *bwtest.HarnessTest) {
	const (
		sourceName  = "account manager locked rename source"
		renamedName = "account manager locked rename"
	)

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	_, err := w.NewAccount(ctx, scope, sourceName)
	require.NoError(h, err, "arrange locked rename source")
	before, err := w.GetAccount(ctx, scope, sourceName)
	require.NoError(h, err, "query locked rename source")
	want := *before
	want.AccountName = renamedName
	require.NoError(h, w.Lock(ctx), "lock wallet")

	// Act.
	err = w.RenameAccount(ctx, scope, sourceName, renamedName)

	// Assert.
	require.NoError(h, err, "rename account while locked")
	renamed, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "query locked-wallet rename")
	assertAccountInfoEqual(h, &want, renamed)

	w = h.ReloadWallet(w)
	durable, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "query reloaded locked-wallet rename")
	assertAccountInfoEqual(h, &want, durable)
}

// testAccountManagerRejectStoppedAccountRename verifies a stopped wallet
// rejects RenameAccount without changing the durable source name.
func testAccountManagerRejectStoppedAccountRename(h *bwtest.HarnessTest) {
	const (
		sourceName  = "account manager stopped rename source"
		renamedName = "account manager stopped rename"
	)

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	_, err := w.NewAccount(ctx, scope, sourceName)
	require.NoError(h, err, "arrange stopped rename source")
	before, err := w.GetAccount(ctx, scope, sourceName)
	require.NoError(h, err, "query stopped rename source")
	require.NoError(h, w.Stop(ctx), "stop wallet")

	// Act.
	err = w.RenameAccount(ctx, scope, sourceName, renamedName)

	// Assert.
	require.ErrorIs(h, err, wallet.ErrStateForbidden)
	w = h.ReloadWallet(w)
	sourceAfter, err := w.GetAccount(ctx, scope, sourceName)
	require.NoError(h, err, "query source after stopped rename")
	assertAccountInfoEqual(h, before, sourceAfter)
	target, err := w.GetAccount(ctx, scope, renamedName)
	require.Error(h, err)
	require.Nil(h, target)
}

// testAccountManagerImportAccount verifies one persistent ImportAccount
// mutation and its immediate durable postcondition.
func testAccountManagerImportAccount(h *bwtest.HarnessTest) {
	const accountName = "account manager imported"

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	addrType := waddrmgr.WitnessPubKey
	_, accountKey, fingerprint := importedAccountFixture(h, 0)
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})

	// Act.
	imported, err := w.ImportAccount(
		ctx, accountName, accountKey, fingerprint, addrType, false,
	)

	// Assert.
	require.NoError(h, err, "import account")
	assertImportedAccountInfoShape(
		h, accountName, accountKey, fingerprint, addrType, imported,
	)
	queried, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "query imported account")
	assertAccountInfoEqual(h, imported, queried)

	w = h.ReloadWallet(w)
	durable, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "query reloaded imported account")
	assertAccountInfoEqual(h, imported, durable)
}

// testAccountManagerPreviewAccountImport verifies a dry run returns the full
// prospective account view without persisting it.
func testAccountManagerPreviewAccountImport(h *bwtest.HarnessTest) {
	const accountName = "account manager import preview"

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	addrType := waddrmgr.WitnessPubKey
	_, accountKey, _ := importedAccountFixture(h, 0)
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})

	// Act.
	preview, err := w.ImportAccount(
		ctx, accountName, accountKey, 0, addrType, true,
	)

	// Assert.
	require.NoError(h, err, "preview account import")
	assertImportedAccountInfoShape(
		h, accountName, accountKey, 0, addrType, preview,
	)
	missing, err := w.GetAccount(ctx, scope, accountName)
	require.Error(h, err)
	require.Nil(h, missing)
}

// testAccountManagerRejectDuplicateImportName verifies a duplicate account
// name cannot replace the imported account that already owns it.
func testAccountManagerRejectDuplicateImportName(h *bwtest.HarnessTest) {
	const accountName = "account manager import duplicate name"

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	addrType := waddrmgr.WitnessPubKey
	_, firstKey, fingerprint := importedAccountFixture(h, 0)
	_, secondKey, _ := importedAccountFixture(h, 1)
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})
	_, err := w.ImportAccount(
		ctx, accountName, firstKey, fingerprint, addrType, false,
	)
	require.NoError(h, err, "arrange imported account")
	before, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "query imported account")

	// Act.
	duplicate, err := w.ImportAccount(
		ctx, accountName, secondKey, fingerprint, addrType, false,
	)

	// Assert.
	require.Error(h, err)
	require.Nil(h, duplicate)
	after, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "query account after duplicate-name rejection")
	assertAccountInfoEqual(h, before, after)
}

// testAccountManagerRejectInvalidImportName verifies ImportAccount name
// validation leaves no account row behind.
func testAccountManagerRejectInvalidImportName(h *bwtest.HarnessTest) {
	const invalidName = ""

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	addrType := waddrmgr.WitnessPubKey
	_, accountKey, fingerprint := importedAccountFixture(h, 0)
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})

	// Act.
	imported, err := w.ImportAccount(
		ctx, invalidName, accountKey, fingerprint, addrType, false,
	)

	// Assert.
	require.Error(h, err)
	require.Nil(h, imported)
	missing, err := w.GetAccount(ctx, scope, invalidName)
	require.Error(h, err)
	require.Nil(h, missing)
}

// testAccountManagerRejectInvalidImportKey verifies malformed account keys
// share the stable public invalid-key identity and persist nothing.
func testAccountManagerRejectInvalidImportKey(h *bwtest.HarnessTest) {
	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	addrType := waddrmgr.WitnessPubKey
	privateKey, _, fingerprint := importedAccountFixture(h, 0)
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})
	tests := []struct {
		name string
		key  *hdkeychain.ExtendedKey
	}{
		{name: "account manager import nil key"},
		{name: "account manager import private key", key: privateKey},
	}

	for _, test := range tests {
		// Act.
		imported, err := w.ImportAccount(
			ctx, test.name, test.key, fingerprint, addrType, false,
		)

		// Assert.
		require.ErrorIs(h, err, wallet.ErrInvalidAccountKey, test.name)
		require.Nil(h, imported, test.name)
		missing, err := w.GetAccount(ctx, scope, test.name)
		require.Error(h, err, test.name)
		require.Nil(h, missing, test.name)
	}
}

// testAccountManagerRejectStoppedAccountImport verifies a stopped wallet
// rejects ImportAccount before persisting the requested account.
func testAccountManagerRejectStoppedAccountImport(h *bwtest.HarnessTest) {
	const accountName = "account manager stopped import"

	// Arrange.
	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	addrType := waddrmgr.WitnessPubKey
	_, accountKey, fingerprint := importedAccountFixture(h, 0)
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})
	require.NoError(h, w.Stop(ctx), "stop wallet")

	// Act.
	imported, err := w.ImportAccount(
		ctx, accountName, accountKey, fingerprint, addrType, false,
	)

	// Assert.
	require.ErrorIs(h, err, wallet.ErrStateForbidden)
	require.Nil(h, imported)
	w = h.ReloadWallet(w)
	missing, err := w.GetAccount(ctx, scope, accountName)
	require.Error(h, err)
	require.Nil(h, missing)
}
