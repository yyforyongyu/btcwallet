//go:build itest

package itest

import "github.com/btcsuite/btcwallet/bwtest"

// testCase defines a single integration test case.
type testCase struct {
	// Name is the human-readable name of the test case.
	Name string

	// TestFunc executes the test case.
	TestFunc func(t *bwtest.HarnessTest)
}

// allTestCases is the full set of integration test cases.
var allTestCases = []*testCase{
	{
		Name:     "manager create wallet",
		TestFunc: testCreateWallet,
	},
	{
		Name:     "manager create duplicate",
		TestFunc: testManagerCreateDuplicate,
	},
	{
		Name:     "manager load reload",
		TestFunc: testManagerLoadReload,
	},
	{
		Name:     "manager load missing",
		TestFunc: testManagerLoadMissing,
	},
	{
		Name:     "manager create watchonly",
		TestFunc: testManagerCreateWatchOnly,
	},
	{
		Name:     "account manager create account",
		TestFunc: testAccountManagerCreateAccount,
	},
	{
		Name:     "account manager reject duplicate creation",
		TestFunc: testAccountManagerRejectDuplicateAccountCreation,
	},
	{
		Name:     "account manager reject invalid creation",
		TestFunc: testAccountManagerRejectInvalidAccountCreation,
	},
	{
		Name:     "account manager reject locked creation",
		TestFunc: testAccountManagerRejectLockedAccountCreation,
	},
	{
		Name:     "account manager reject watchonly creation",
		TestFunc: testAccountManagerRejectWatchOnlyAccountCreation,
	},
	{
		Name:     "account manager reject stopped creation",
		TestFunc: testAccountManagerRejectStoppedAccountCreation,
	},
	{
		Name:     "account manager rename derived account",
		TestFunc: testAccountManagerRenameDerivedAccount,
	},
	{
		Name:     "account manager rename imported account",
		TestFunc: testAccountManagerRenameImportedAccount,
	},
	{
		Name:     "account manager reject duplicate rename",
		TestFunc: testAccountManagerRejectDuplicateAccountRename,
	},
	{
		Name:     "account manager reject invalid rename",
		TestFunc: testAccountManagerRejectInvalidAccountRename,
	},
	{
		Name:     "account manager reject unknown rename",
		TestFunc: testAccountManagerRejectUnknownAccountRename,
	},
	{
		Name:     "account manager rename locked account",
		TestFunc: testAccountManagerRenameLockedAccount,
	},
	{
		Name:     "account manager reject stopped rename",
		TestFunc: testAccountManagerRejectStoppedAccountRename,
	},
	{
		Name:     "account manager import account",
		TestFunc: testAccountManagerImportAccount,
	},
	{
		Name:     "account manager preview import",
		TestFunc: testAccountManagerPreviewAccountImport,
	},
	{
		Name:     "account manager reject duplicate import name",
		TestFunc: testAccountManagerRejectDuplicateImportName,
	},
	{
		Name:     "account manager reject invalid import name",
		TestFunc: testAccountManagerRejectInvalidImportName,
	},
	{
		Name:     "account manager reject invalid import key",
		TestFunc: testAccountManagerRejectInvalidImportKey,
	},
	{
		Name:     "account manager reject stopped import",
		TestFunc: testAccountManagerRejectStoppedAccountImport,
	},
	{
		Name:     "controller start stop",
		TestFunc: testControllerStartStop,
	},
	{
		Name:     "controller unlock lock",
		TestFunc: testControllerUnlockLock,
	},
	{
		Name:     "controller info",
		TestFunc: testControllerInfo,
	},
	{
		Name:     "utxomanager list unspent",
		TestFunc: testListUnspent,
	},
	{
		Name:     "utxomanager list unspent unconfirmed",
		TestFunc: testListUnspentUnconfirmed,
	},
	{
		Name:     "utxomanager list unspent immature coinbase",
		TestFunc: testListUnspentImmatureCoinbase,
	},
	{
		Name:     "utxomanager get utxo",
		TestFunc: testGetUtxo,
	},
	{
		Name:     "utxomanager lease output",
		TestFunc: testLeaseOutput,
	},
	{
		Name:     "utxomanager release output",
		TestFunc: testReleaseOutput,
	},
	{
		Name:     "utxomanager list leased outputs",
		TestFunc: testListLeasedOutputs,
	},
	{
		Name:     "txcreator select coins",
		TestFunc: testCreateTransactionSelectCoins,
	},
	{
		Name:     "txcreator multiple outputs",
		TestFunc: testCreateTransactionMultipleOutputs,
	},
	{
		Name:     "txcreator manual inputs",
		TestFunc: testCreateTransactionManualInputs,
	},
	{
		Name:     "txcreator default account",
		TestFunc: testCreateTransactionDefaultAccount,
	},
	{
		Name:     "txcreator coin source",
		TestFunc: testCreateTransactionCoinSource,
	},
	{
		Name:     "txcreator omit change",
		TestFunc: testCreateTransactionOmitChange,
	},
	{
		Name:     "txcreator reject intent",
		TestFunc: testCreateTransactionRejectIntent,
	},
	{
		Name:     "txcreator output boundaries",
		TestFunc: testCreateTransactionOutputBoundaries,
	},
	{
		Name:     "txcreator reject inputs",
		TestFunc: testCreateTransactionRejectInputs,
	},
	{
		Name:     "txcreator wallet state",
		TestFunc: testCreateTransactionWalletState,
	},
}
