// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestAddressInfoFromManagedAddressPubKey verifies conversion of a managed
// pubkey address into wallet-owned metadata.
func TestAddressInfoFromManagedAddressPubKey(t *testing.T) {
	t.Parallel()

	// Arrange: Create one managed pubkey address mock with derivation data.
	_, mocks := createStartedWalletWithMocks(t)
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(privKey.PubKey().SerializeCompressed()),
		&chainParams,
	)
	require.NoError(t, err)

	mocks.pubKeyAddr.On("Address").Return(addr).Once()
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Once()
	mocks.pubKeyAddr.On("Imported").Return(false).Once()
	mocks.pubKeyAddr.On("Internal").Return(true).Once()
	mocks.pubKeyAddr.On("Compressed").Return(true).Once()
	mocks.pubKeyAddr.On("PubKey").Return(privKey.PubKey()).Once()
	mocks.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScopeBIP0084,
		waddrmgr.DerivationPath{
			Account:              1,
			Branch:               1,
			Index:                7,
			MasterKeyFingerprint: 99,
		},
		true,
	).Once()

	// Act: Convert the managed address into wallet-owned metadata.
	info, err := addressInfoFromManagedAddress(mocks.pubKeyAddr)
	require.NoError(t, err)

	// Assert: The converted metadata retains the managed address fields and
	// derivation information.
	require.Equal(t, addr, info.Addr)
	require.Equal(t, waddrmgr.WitnessPubKey, info.AddrType)
	require.False(t, info.Imported)
	require.True(t, info.Internal)
	require.True(t, info.Compressed)
	require.Equal(t, privKey.PubKey(), info.PubKey)
	require.NotNil(t, info.Derivation)
	require.Equal(t, waddrmgr.KeyScopeBIP0084, info.Derivation.KeyScope)
	require.Equal(t, uint32(1), info.Derivation.Account)
	require.Equal(t, uint32(1), info.Derivation.Branch)
	require.Equal(t, uint32(7), info.Derivation.Index)
	require.Equal(t, uint32(99), info.Derivation.MasterKeyFingerprint)
}

// TestOutputScriptInfoFromManagedAddress verifies conversion of script data
// alongside the wallet-owned address metadata.
func TestOutputScriptInfoFromManagedAddress(t *testing.T) {
	t.Parallel()

	// Arrange: Create one imported managed address mock and sample script data.
	_, mocks := createStartedWalletWithMocks(t)
	addr, err := btcutil.NewAddressScriptHash(make([]byte, 20), &chainParams)
	require.NoError(t, err)

	mocks.addr.On("Address").Return(addr).Once()
	mocks.addr.On("AddrType").Return(waddrmgr.Script).Once()
	mocks.addr.On("Imported").Return(true).Once()
	mocks.addr.On("Internal").Return(false).Once()
	mocks.addr.On("Compressed").Return(false).Once()

	witnessProgram, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Act: Convert the managed address and scripts into wallet-owned output
	// metadata.
	info, err := outputScriptInfoFromManagedAddress(
		mocks.addr, witnessProgram, []byte{txscript.OP_TRUE},
	)
	require.NoError(t, err)

	// Assert: The output metadata retains the managed-address fields and script
	// payloads.
	require.Equal(t, addr, info.Addr)
	require.Equal(t, waddrmgr.Script, info.AddrType)
	require.True(t, info.Imported)
	require.Nil(t, info.PubKey)
	require.Nil(t, info.Derivation)
	require.Equal(t, witnessProgram, info.WitnessProgram)
	require.Equal(t, []byte{txscript.OP_TRUE}, info.RedeemScript)
}
