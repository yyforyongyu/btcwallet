// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func addressInfoFromAddr(t *testing.T, addr btcutil.Address) *db.AddressInfo {
	t.Helper()

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return &db.AddressInfo{ScriptPubKey: pkScript}
}

func expectStoreNewAddress(t *testing.T, w *Wallet, deps *mockWalletDeps,
	accountName string, scope waddrmgr.KeyScope, change bool,
	addr btcutil.Address) {

	t.Helper()

	deps.store.On(
		"NewDerivedAddress", mock.Anything,
		db.NewDerivedAddressParams{
			WalletID:    w.id,
			AccountName: accountName,
			Scope:       db.KeyScope(scope),
			Change:      change,
		}, mock.Anything,
	).Return(addressInfoFromAddr(t, addr), nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{addr}).Return(nil).Once()
}

func expectStoreManagedAddress(t *testing.T, w *Wallet, deps *mockWalletDeps,
	addr btcutil.Address, managedAddr waddrmgr.ManagedAddress) {

	t.Helper()

	deps.store.On("GetManagedAddress", mock.Anything, db.GetManagedAddressQuery{
		WalletID: w.id,
		Address:  addr.EncodeAddress(),
	}).Return(managedAddr, nil).Once()
}

// TestNewAddress tests the NewAddress method, ensuring it can generate
// various address types for different accounts and correctly handles both
// internal and external address generation.
func TestNewAddress(t *testing.T) {
	t.Parallel()

	// Define a set of test cases to cover different address types and
	// scenarios.
	testCases := []struct {
		name             string
		accountName      string
		addrType         waddrmgr.AddressType
		change           bool
		expectErr        bool
		expectedAddrType btcutil.Address
	}{
		{
			name:             "default account p2wkh",
			accountName:      "default",
			addrType:         waddrmgr.WitnessPubKey,
			change:           false,
			expectedAddrType: &btcutil.AddressWitnessPubKeyHash{},
		},
		{
			name:             "p2wkh change address",
			accountName:      "default",
			addrType:         waddrmgr.WitnessPubKey,
			change:           true,
			expectedAddrType: &btcutil.AddressWitnessPubKeyHash{},
		},
		{
			name:             "default account np2wkh",
			accountName:      "default",
			addrType:         waddrmgr.NestedWitnessPubKey,
			change:           false,
			expectedAddrType: &btcutil.AddressScriptHash{},
		},
		{
			name:             "default account p2tr",
			accountName:      "default",
			addrType:         waddrmgr.TaprootPubKey,
			change:           false,
			expectedAddrType: &btcutil.AddressTaproot{},
		},
		{
			name:        "unknown address type",
			accountName: "default",
			addrType:    waddrmgr.WitnessScript,
			expectErr:   true,
		},
		{
			name:        "imported account",
			accountName: waddrmgr.ImportedAddrAccountName,
			addrType:    waddrmgr.WitnessPubKey,
			expectErr:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, deps := createStartedWalletWithMocks(t)

			if tc.expectErr {
				_, err := w.NewAddress(
					t.Context(), tc.accountName,
					tc.addrType, tc.change,
				)
				require.Error(t, err)

				return
			}

			var addr btcutil.Address
			switch tc.addrType {
			case waddrmgr.WitnessPubKey:
				addr, _ = btcutil.NewAddressWitnessPubKeyHash(
					make([]byte, 20), w.cfg.ChainParams,
				)
			case waddrmgr.NestedWitnessPubKey:
				addr, _ = btcutil.NewAddressScriptHash(
					make([]byte, 20), w.cfg.ChainParams,
				)
			case waddrmgr.TaprootPubKey:
				addr, _ = btcutil.NewAddressTaproot(
					make([]byte, 32), w.cfg.ChainParams,
				)
			case waddrmgr.PubKeyHash, waddrmgr.Script,
				waddrmgr.RawPubKey, waddrmgr.WitnessScript,
				waddrmgr.TaprootScript:

				require.FailNow(t, "unhandled address type", tc.addrType)

			default:
				require.FailNow(t, "unknown address type", tc.addrType)
			}

			scope, ok := tc.addrType.KeyScope()
			require.True(t, ok)

			expectStoreNewAddress(
				t, w, deps, tc.accountName, scope, tc.change, addr,
			)
			expectStoreManagedAddress(t, w, deps, addr, deps.addr)
			deps.addr.On("Address").Return(addr).Once()
			deps.addr.On("AddrType").Return(tc.addrType).Once()
			deps.addr.On("Imported").Return(false).Once()
			deps.addr.On("Internal").Return(tc.change).Once()
			deps.addr.On("Compressed").Return(true).Once()

			addr, err := w.NewAddress(
				t.Context(), tc.accountName,
				tc.addrType, tc.change,
			)
			require.NoError(t, err)
			require.NotNil(t, addr)

			require.IsType(t, tc.expectedAddrType, addr)

			addrInfo, err := w.GetAddressInfo(t.Context(), addr)
			require.NoError(t, err)
			require.Equal(t, tc.change, addrInfo.Internal)
		})
	}
}

// TestGetUnusedAddress tests the GetUnusedAddress method to ensure it
// correctly returns the earliest unused address.
func TestGetUnusedAddress(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	firstAddr, _ := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	scope := waddrmgr.KeyScopeBIP0084

	deps.store.On("FindUnusedAddress", mock.Anything, db.FindUnusedAddressQuery{
		WalletID:    w.id,
		AccountName: "default",
		Scope:       db.KeyScope(scope),
		Change:      false,
	}).Return(firstAddr, nil).Once()

	unusedAddr, err := w.GetUnusedAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)
	require.Equal(t, firstAddr.String(), unusedAddr.String())

	deps.store.On("FindUnusedAddress", mock.Anything, db.FindUnusedAddressQuery{
		WalletID:    w.id,
		AccountName: "default",
		Scope:       db.KeyScope(scope),
		Change:      false,
	}).Return(nil, nil).Once()

	nextAddrVal, _ := btcutil.NewAddressWitnessPubKeyHash(
		[]byte{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		}, w.cfg.ChainParams,
	)
	expectStoreNewAddress(t, w, deps, "default", scope, false, nextAddrVal)

	nextAddr, err := w.GetUnusedAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// The next unused address should not be the same as the first one.
	require.NotEqual(t, firstAddr.String(), nextAddr.String())

	changeAddrVal, _ := btcutil.NewAddressWitnessPubKeyHash(
		[]byte{
			21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
			31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		}, w.cfg.ChainParams,
	)

	deps.store.On("FindUnusedAddress", mock.Anything, db.FindUnusedAddressQuery{
		WalletID:    w.id,
		AccountName: "default",
		Scope:       db.KeyScope(scope),
		Change:      true,
	}).Return(changeAddrVal, nil).Once()

	unusedChangeAddr, err := w.GetUnusedAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, true,
	)
	require.NoError(t, err)
	require.Equal(t, changeAddrVal.String(), unusedChangeAddr.String())
}

// TestGetAddressInfo tests the GetAddressInfo method to ensure it returns
// information for both internal and external addresses.
func TestGetAddressInfo(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	extAddr, _ := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	expectStoreManagedAddress(t, w, deps, extAddr, deps.addr)
	deps.addr.On("Address").Return(extAddr).Once()
	deps.addr.On("Internal").Return(false).Once()
	deps.addr.On("Compressed").Return(true).Once()
	deps.addr.On("Imported").Return(false).Once()
	deps.addr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()

	extInfo, err := w.GetAddressInfo(t.Context(), extAddr)
	require.NoError(t, err)

	require.Equal(t, extAddr.String(), extInfo.Addr.String())
	require.False(t, extInfo.Internal)
	require.True(t, extInfo.Compressed)
	require.False(t, extInfo.Imported)
	require.Equal(t, waddrmgr.WitnessPubKey, extInfo.AddrType)

	intAddr, _ := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	expectStoreManagedAddress(t, w, deps, intAddr, deps.addr)
	deps.addr.On("Address").Return(intAddr).Once()
	deps.addr.On("Internal").Return(true).Once()
	deps.addr.On("Compressed").Return(true).Once()
	deps.addr.On("Imported").Return(false).Once()
	deps.addr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()

	intInfo, err := w.GetAddressInfo(t.Context(), intAddr)
	require.NoError(t, err)

	require.Equal(t, intAddr.String(), intInfo.Addr.String())
	require.True(t, intInfo.Internal)
	require.True(t, intInfo.Compressed)
	require.False(t, intInfo.Imported)
	require.Equal(t, waddrmgr.WitnessPubKey, intInfo.AddrType)
}

// TestGetDerivationInfoExternalAddressSuccess tests that we can successfully
// get the derivation info for an external address.
func TestGetDerivationInfoExternalAddressSuccess(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)
	addr, _ := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	expectStoreManagedAddress(t, w, deps, addr, deps.pubKeyAddr)
	deps.pubKeyAddr.On("Address").Return(addr).Once()
	deps.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()
	deps.pubKeyAddr.On("Imported").Return(false).Once()
	deps.pubKeyAddr.On("Internal").Return(false).Once()
	deps.pubKeyAddr.On("Compressed").Return(true).Once()

	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()
	deps.pubKeyAddr.On("PubKey").Return(pubKey).Once()

	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{
		Account:              0,
		Branch:               0,
		Index:                0,
		MasterKeyFingerprint: 123,
	}
	deps.pubKeyAddr.On("DerivationInfo").Return(scope, path, true).Once()

	derivationInfo, err := w.GetDerivationInfo(t.Context(), addr)

	require.NoError(t, err)
	require.NotNil(t, derivationInfo)

	expectedPath := []uint32{
		scope.Purpose + hdkeychain.HardenedKeyStart,
		scope.Coin + hdkeychain.HardenedKeyStart,
		path.Account + hdkeychain.HardenedKeyStart,
		path.Branch,
		path.Index,
	}

	require.Equal(t, pubKey.SerializeCompressed(), derivationInfo.PubKey)
	require.Equal(t, path.MasterKeyFingerprint,
		derivationInfo.MasterKeyFingerprint)
	require.Equal(t, expectedPath, derivationInfo.Bip32Path)
}

// TestGetDerivationInfoInternalAddressSuccess tests that we can successfully
// get the derivation info for an internal address.
func TestGetDerivationInfoInternalAddressSuccess(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)
	addr, _ := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	expectStoreManagedAddress(t, w, deps, addr, deps.pubKeyAddr)
	deps.pubKeyAddr.On("Address").Return(addr).Once()
	deps.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()
	deps.pubKeyAddr.On("Imported").Return(false).Once()
	deps.pubKeyAddr.On("Internal").Return(true).Once()
	deps.pubKeyAddr.On("Compressed").Return(true).Once()

	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()
	deps.pubKeyAddr.On("PubKey").Return(pubKey).Once()

	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{
		Account:              0,
		Branch:               1,
		Index:                0,
		MasterKeyFingerprint: 123,
	}
	deps.pubKeyAddr.On("DerivationInfo").Return(scope, path, true).Once()

	derivationInfo, err := w.GetDerivationInfo(t.Context(), addr)

	require.NoError(t, err)
	require.NotNil(t, derivationInfo)

	expectedPath := []uint32{
		scope.Purpose + hdkeychain.HardenedKeyStart,
		scope.Coin + hdkeychain.HardenedKeyStart,
		path.Account + hdkeychain.HardenedKeyStart,
		path.Branch,
		path.Index,
	}
	require.Equal(t, expectedPath, derivationInfo.Bip32Path)
	require.Equal(t, uint32(1), path.Branch)
}

// TestGetDerivationInfoNoDerivationInfo tests that we get an error when trying
// to get the derivation info for an address that is not in the wallet or is
// imported.
func TestGetDerivationInfoNoDerivationInfo(t *testing.T) {
	t.Parallel()

	// Arrange: Create a new test wallet and a key and address that is not
	// in the wallet.
	w, deps := createStartedWalletWithMocks(t)
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Act & Assert: Check that we get an error for an address not in the
	// wallet.
	deps.store.On("GetManagedAddress", mock.Anything, db.GetManagedAddressQuery{
		WalletID: w.id,
		Address:  addr.EncodeAddress(),
	}).Return(
		nil, errDBMock).Once()

	_, err = w.GetDerivationInfo(t.Context(), addr)
	require.Error(t, err)

	// Arrange: Import the key as a watch-only address.
	deps.store.On("ImportPublicKey", mock.Anything, db.ImportPublicKeyParams{
		WalletID:         w.id,
		Scope:            db.KeyScope(waddrmgr.KeyScopeBIP0084),
		SerializedPubKey: pubKey.SerializeCompressed(),
	}).Return(addr, nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{addr}).
		Return(nil).Once()

	err = w.ImportPublicKey(t.Context(), pubKey, waddrmgr.WitnessPubKey)
	require.NoError(t, err)

	// Act & Assert: Check that we still get an error because it's an
	// imported key.
	expectStoreManagedAddress(t, w, deps, addr, deps.pubKeyAddr)
	deps.pubKeyAddr.On("Imported").Return(true).Once()
	deps.pubKeyAddr.On("Address").Return(addr).Once()
	deps.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()
	deps.pubKeyAddr.On("Internal").Return(false).Once()
	deps.pubKeyAddr.On("Compressed").Return(true).Once()
	deps.pubKeyAddr.On("PubKey").Return(pubKey).Once()
	deps.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScope{}, waddrmgr.DerivationPath{}, false,
	).Once()

	_, err = w.GetDerivationInfo(t.Context(), addr)
	require.ErrorIs(t, err, ErrDerivationPathNotFound)
}

// TestListAddresses tests the ListAddresses method to ensure it returns the
// correct addresses and balances for a given account.
func TestListAddresses(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	addr, _ := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	deps.store.On("ListAddresses", mock.Anything, db.ListAddressesQuery{
		WalletID:    w.id,
		AccountName: "default",
		Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
	}).Return(page.Result[db.AddressInfo, uint32]{
		Items: []db.AddressInfo{{ScriptPubKey: pkScript}},
	}, nil).Once()
	deps.store.On("ListUTXOs", mock.Anything, db.ListUtxosQuery{
		WalletID: w.id,
	}).Return([]db.UtxoInfo{{Amount: 1000, PkScript: pkScript}}, nil).Once()

	addrs, err := w.ListAddresses(
		t.Context(), "default", waddrmgr.WitnessPubKey,
	)
	require.NoError(t, err)

	// We should have one address with a balance of 1000.
	require.Len(t, addrs, 1)
	require.Equal(t, addr.String(), addrs[0].Address.String())
	require.Equal(t, btcutil.Amount(1000), addrs[0].Balance)
}

// TestImportPublicKey tests the ImportPublicKey method to ensure it can
// import a public key as a watch-only address.
func TestImportPublicKey(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	addr, _ := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)

	deps.store.On("ImportPublicKey", mock.Anything, db.ImportPublicKeyParams{
		WalletID:         w.id,
		Scope:            db.KeyScope(waddrmgr.KeyScopeBIP0084),
		SerializedPubKey: pubKey.SerializeCompressed(),
	}).Return(addr, nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{addr}).
		Return(nil).Once()

	err = w.ImportPublicKey(t.Context(), pubKey, waddrmgr.WitnessPubKey)
	require.NoError(t, err)

	expectStoreManagedAddress(t, w, deps, addr, deps.pubKeyAddr)
	deps.pubKeyAddr.On("Address").Return(addr).Once()
	deps.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()
	deps.pubKeyAddr.On("Imported").Return(true).Once()
	deps.pubKeyAddr.On("Internal").Return(false).Once()
	deps.pubKeyAddr.On("Compressed").Return(true).Once()
	deps.pubKeyAddr.On("PubKey").Return(pubKey).Once()
	deps.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScope{}, waddrmgr.DerivationPath{}, false,
	).Once()

	info, err := w.GetAddressInfo(t.Context(), addr)
	require.NoError(t, err)
	require.NotNil(t, info)
}

// TestImportTaprootScript tests the ImportTaprootScript method to ensure it can
// import a taproot script as a watch-only address.
func TestImportTaprootScript(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	// Create a new tapscript to import.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	script, err := txscript.NewScriptBuilder().
		AddData(pubKey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	leaf := txscript.NewTapLeaf(txscript.BaseLeafVersion, script)
	tree := txscript.AssembleTaprootScriptTree(leaf)
	rootHash := tree.RootNode.TapHash()
	tapscript := waddrmgr.Tapscript{
		Type: waddrmgr.TapscriptTypeFullTree,
		ControlBlock: &txscript.ControlBlock{
			InternalKey: pubKey,
		},
		Leaves: []txscript.TapLeaf{leaf},
	}

	addr, _ := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(txscript.ComputeTaprootOutputKey(
			pubKey, rootHash[:],
		)), w.cfg.ChainParams,
	)

	deps.store.On("ImportTaprootScript", mock.Anything,
		db.ImportTaprootScriptParams{
			WalletID:       w.id,
			Tapscript:      tapscript,
			SyncedTo:       waddrmgr.BlockStamp{Height: 1},
			WitnessVersion: 1,
			IsSecretScript: false,
		},
	).Return(addr, nil).Once()
	deps.chain.On("NotifyReceived", []btcutil.Address{addr}).
		Return(nil).Once()
	expectStoreManagedAddress(t, w, deps, addr, deps.taprootAddr)
	deps.taprootAddr.On("Address").Return(addr).Once()
	deps.taprootAddr.On("AddrType").Return(waddrmgr.TaprootScript).Once()
	deps.taprootAddr.On("Imported").Return(true).Once()
	deps.taprootAddr.On("Internal").Return(false).Once()
	deps.taprootAddr.On("Compressed").Return(false).Once()

	info, err := w.ImportTaprootScript(t.Context(), tapscript)
	require.NoError(t, err)
	require.Equal(t, addr, info.Addr)
	require.Equal(t, waddrmgr.TaprootScript, info.AddrType)
	require.True(t, info.Imported)
}

// TestScriptForOutput tests the ScriptForOutput method to ensure it returns the
// correct script for a given output.
func TestScriptForOutput(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	addr, _ := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	output := wire.TxOut{
		Value:    1000,
		PkScript: pkScript,
	}

	_, pubKey := deterministicPrivKey(t)
	expectStoreManagedAddress(t, w, deps, addr, deps.pubKeyAddr)
	deps.pubKeyAddr.On("Address").Return(addr).Once()
	deps.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()
	deps.pubKeyAddr.On("Imported").Return(false).Once()
	deps.pubKeyAddr.On("Internal").Return(false).Once()
	deps.pubKeyAddr.On("Compressed").Return(true).Once()
	deps.pubKeyAddr.On("PubKey").Return(pubKey).Once()
	deps.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScopeBIP0084, waddrmgr.DerivationPath{}, false,
	).Once()

	script, err := w.ScriptForOutput(t.Context(), output)
	require.NoError(t, err)

	// Check that the script is correct.
	require.Equal(t, addr, script.Addr)
	require.Equal(t, waddrmgr.WitnessPubKey, script.AddrType)
	require.Equal(t, pkScript, script.WitnessProgram)
	require.Nil(t, script.RedeemScript)
}

// TestScriptForOutputNestedWitness tests that ScriptForOutput carries the
// redeem script needed for nested witness outputs.
func TestScriptForOutputNestedWitness(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)
	_, pubKey := deterministicPrivKey(t)
	witnessProgram, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(btcutil.Hash160(pubKey.SerializeCompressed())).
		Script()
	require.NoError(t, err)

	addr, err := btcutil.NewAddressScriptHash(witnessProgram, w.cfg.ChainParams)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	expectedSigScript, err := waddrmgr.NestedWitnessPubKey.
		RedeemScriptFromPubKey(pubKey, w.cfg.ChainParams)
	require.NoError(t, err)

	expectStoreManagedAddress(t, w, deps, addr, deps.pubKeyAddr)
	deps.pubKeyAddr.On("Address").Return(addr).Once()
	deps.pubKeyAddr.On("AddrType").Return(waddrmgr.NestedWitnessPubKey).Once()
	deps.pubKeyAddr.On("Imported").Return(false).Once()
	deps.pubKeyAddr.On("Internal").Return(false).Once()
	deps.pubKeyAddr.On("Compressed").Return(true).Once()
	deps.pubKeyAddr.On("PubKey").Return(pubKey).Once()
	deps.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScopeBIP0049Plus, waddrmgr.DerivationPath{}, false,
	).Once()

	scriptInfo, err := w.ScriptForOutput(t.Context(), wire.TxOut{
		Value:    1000,
		PkScript: pkScript,
	})
	require.NoError(t, err)
	require.Equal(t, addr, scriptInfo.Addr)
	require.Equal(t, waddrmgr.NestedWitnessPubKey,
		scriptInfo.AddrType)
	require.Equal(t, witnessProgram, scriptInfo.WitnessProgram)
	require.Equal(t, witnessProgram, scriptInfo.RedeemScript)
	require.Equal(t, expectedSigScript, scriptInfo.SigScript)
}
