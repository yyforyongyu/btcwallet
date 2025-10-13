// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

var (
	// ErrDerivationPathNotFound is returned when the derivation path for a
	// given script cannot be found. This may be because the script does
	// not belong to the wallet, is imported, or is not a pubkey-based
	// script.
	ErrDerivationPathNotFound = errors.New("derivation path not found")

	// ErrUnknownAddrType is an error returned when a wallet function is
	// called with an unknown address type.
	ErrUnknownAddrType = errors.New("unknown address type")

	// ErrImportedAccountNoAddrGen is an error returned when a new address
	// is requested for the default imported account within the wallet.
	ErrImportedAccountNoAddrGen = errors.New("addresses cannot be " +
		"generated for the default imported account")
)

// AddressProperty represents an address and its balance.
type AddressProperty struct {
	Address db.AddressInfo
	Balance btcutil.Amount
}

// Script represents the script information required to spend a UTXO.
type Script struct {
	// Addr is the managed address of the UTXO.
	Addr db.AddressInfo

	// WitnessProgram is the witness program of the UTXO.
	WitnessProgram []byte

	// RedeemScript is the redeem script of the UTXO.
	RedeemScript []byte
}

// AddressManager provides an interface for generating and inspecting wallet
// addresses and scripts.
type AddressManager interface {
	// NewAddress returns a new address for the given account and address
	// type.
	//
	// NOTE: This method should be used with caution. Unlike
	// GetUnusedAddress, it does not scan for previously derived but unused
	// addresses. Using this method repeatedly can create gaps in the
	// address chain, which may negatively impact wallet recovery under
	// BIP44. It is primarily intended for advanced use cases such as bulk
	// address generation.
	NewAddress(ctx context.Context, accountName string,
		addrType waddrmgr.AddressType,
		change bool) (btcutil.Address, error)

	// GetUnusedAddress returns the first, oldest, unused address by scanning
	// forward from the start of the derivation path. This method is the
	// recommended default for obtaining a new receiving address, as it
	// prevents address reuse and avoids creating gaps in the address chain
	// that could impact wallet recovery.
	GetUnusedAddress(ctx context.Context, accountName string,
		addrType db.AddressType, change bool) (
		btcutil.Address, error)

	// AddressInfo returns detailed information about a managed address. If
	// the address is not known to the wallet, an error is returned.
	AddressInfo(ctx context.Context,
		a btcutil.Address) (db.AddressInfo, error)

	// ListAddresses lists all addresses for a given account, including
	// their balances.
	ListAddresses(ctx context.Context, accountName string,
		addrType db.AddressType) ([]AddressProperty, error)

	// ImportPublicKey imports a single public key as a watch-only address.
	ImportPublicKey(ctx context.Context, pubKey *btcec.PublicKey,
		addrType db.AddressType) error

	// ImportTaprootScript imports a taproot script for tracking and
	// spending.
	ImportTaprootScript(ctx context.Context,
		tapscript db.Tapscript) (db.AddressInfo, error)

	// ScriptForOutput returns the address, witness program, and redeem
	// script for a given UTXO.
	ScriptForOutput(ctx context.Context, output wire.TxOut) (Script, error)

	// GetDerivationInfo returns the BIP-32 derivation path for a given
	// address.
	GetDerivationInfo(ctx context.Context,
		addr btcutil.Address) (*psbt.Bip32Derivation, error)
}

// A compile time check to ensure that Wallet implements the interface.
var _ AddressManager = (*Wallet)(nil)

// NewAddress returns a new address for the given account and address type.
func (w *Wallet) NewAddress(ctx context.Context, accountName string,
	addrType waddrmgr.AddressType, change bool) (btcutil.Address, error) {

	if accountName == waddrmgr.ImportedAddrAccountName {
		return nil, ErrImportedAccountNoAddrGen
	}

	dbAddrType := db.AddressType(addrType)
	keyScope, err := w.keyScopeFromAddrType(dbAddrType)
	if err != nil {
		return nil, err
	}

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	params := db.CreateAddressParams{
		WalletID:    w.ID(),
		AccountName: accountName,
		Scope:       keyScope,
		Change:      change,
	}
	addrInfo, err := w.store.CreateAddress(ctx, params)
	if err != nil {
		return nil, err
	}

	addr := addrInfo.Address
	err = chainClient.NotifyReceived([]btcutil.Address{addr})
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// keyScopeFromAddrType determines the appropriate key scope for a given
// address type.
func (w *Wallet) keyScopeFromAddrType(
	addrType db.AddressType) (db.KeyScope, error) {

	var keyScope db.KeyScope
	switch addrType {
	case db.AddressType(waddrmgr.WitnessPubKey):
		keyScope = db.KeyScope{
			Purpose: 84,
			Coin:    w.chainParams.HDCoinType,
		}
	case db.AddressType(waddrmgr.NestedWitnessPubKey):
		keyScope = db.KeyScope{
			Purpose: 49,
			Coin:    w.chainParams.HDCoinType,
		}
	case db.AddressType(waddrmgr.TaprootPubKey):
		keyScope = db.KeyScope{
			Purpose: 86,
			Coin:    w.chainParams.HDCoinType,
		}
	default:
		return db.KeyScope{}, fmt.Errorf("%w: %v",
			ErrUnknownAddrType, addrType)
	}

	return keyScope, nil
}

// GetUnusedAddress returns the first, oldest, unused address.
func (w *Wallet) GetUnusedAddress(ctx context.Context, accountName string,
	addrType db.AddressType, change bool) (btcutil.Address, error) {

	if accountName == waddrmgr.ImportedAddrAccountName {
		return nil, ErrImportedAccountNoAddrGen
	}

	keyScope, err := w.keyScopeFromAddrType(addrType)
	if err != nil {
		return nil, err
	}

	addrInfo, err := w.store.CreateAddress(ctx, db.CreateAddressParams{
		WalletID:    w.ID(),
		AccountName: accountName,
		Scope:       keyScope,
		Change:      change,
	})
	if err != nil {
		return nil, err
	}

	return addrInfo.Address, nil
}

// AddressInfo returns detailed information regarding a wallet address.
func (w *Wallet) AddressInfo(ctx context.Context,
	a btcutil.Address) (db.AddressInfo, error) {

	query := db.GetAddressQuery{
		WalletID: w.ID(),
		Address:  a,
	}
	return w.store.GetAddress(ctx, query)
}

// ListAddresses lists all addresses for a given account, including their
// balances.
func (w *Wallet) ListAddresses(ctx context.Context, accountName string,
	addrType db.AddressType) ([]AddressProperty, error) {

	keyScope, err := w.keyScopeFromAddrType(addrType)
	if err != nil {
		return nil, err
	}

	query := db.ListAddressesQuery{
		WalletID:    w.ID(),
		AccountName: accountName,
		Scope:       keyScope,
	}
	addresses, err := w.store.ListAddresses(ctx, query)
	if err != nil {
		return nil, err
	}

	// TODO(yy): Get balances.
	properties := make([]AddressProperty, len(addresses))
	for i, addr := range addresses {
		properties[i] = AddressProperty{
			Address: addr,
		}
	}

	return properties, nil
}

// ImportPublicKey imports a single public key as a watch-only address.
func (w *Wallet) ImportPublicKey(ctx context.Context, pubKey *btcec.PublicKey,
	addrType db.AddressType) error {

	keyScope, err := w.keyScopeFromAddrType(addrType)
	if err != nil {
		return err
	}

	params := db.ImportAddressData{
		WalletID: w.ID(),
		PubKey:   pubKey,
		Scope:    keyScope,
	}
	_, err = w.store.ImportAddress(ctx, params)
	return err
}

// ImportTaprootScript imports a taproot script for tracking and spending.
func (w *Wallet) ImportTaprootScript(ctx context.Context,
	tapscript db.Tapscript) (db.AddressInfo, error) {

	params := db.ImportAddressData{
		WalletID:  w.ID(),
		Tapscript: &tapscript,
	}
	return w.store.ImportAddress(ctx, params)
}

// ScriptForOutput returns the address, witness program, and redeem script
// for a given UTXO.
func (w *Wallet) ScriptForOutput(ctx context.Context, output wire.TxOut) (
	Script, error) {

	addr := extractAddrFromPKScript(output.PkScript, w.chainParams)
	if addr == nil {
		return Script{}, fmt.Errorf("unable to extract address "+
			"from pkscript %x", output.PkScript)
	}

	addrInfo, err := w.store.GetAddress(ctx, db.GetAddressQuery{
		WalletID: w.ID(),
		Address:  addr,
	})
	if err != nil {
		return Script{}, fmt.Errorf("unable to get address info "+
			"for %s: %w", addr.String(), err)
	}

	var (
		witnessProgram []byte
		sigScript      []byte
	)

	switch {
	case addrInfo.AddrType == db.AddressType(waddrmgr.NestedWitnessPubKey):
		// This is a messy conversion.
		// TODO(yy): clean this up.
		info, err := w.store.GetAddress(ctx, db.GetAddressQuery{
			WalletID: w.ID(),
			Address:  addr,
		})
		if err != nil {
			return Script{}, err
		}
		var managedAddr waddrmgr.ManagedAddress = &managedAddress{info: info}
		pubKeyAddr, _ := managedAddr.(waddrmgr.ManagedPubKeyAddress)
		pubKey := pubKeyAddr.PubKey()
		pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())

		p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
			pubKeyHash, w.chainParams,
		)
		if err != nil {
			return Script{}, err
		}
		witnessProgram, err = txscript.PayToAddrScript(p2wkhAddr)
		if err != nil {
			return Script{}, err
		}

		bldr := txscript.NewScriptBuilder()
		bldr.AddData(witnessProgram)
		sigScript, err = bldr.Script()
		if err != nil {
			return Script{}, err
		}

	default:
		witnessProgram = output.PkScript
	}

	return Script{
		Addr:           addrInfo,
		WitnessProgram: witnessProgram,
		RedeemScript:   sigScript,
	}, nil
}

// GetDerivationInfo returns the BIP-32 derivation path for a given address.
func (w *Wallet) GetDerivationInfo(ctx context.Context,
	addr btcutil.Address) (*psbt.Bip32Derivation, error) {

	addrInfo, err := w.AddressInfo(ctx, addr)
	if err != nil {
		return nil, err
	}

	// TODO(yy): check for imported addresses.

	deriv := addrInfo.DerivationInfo
	derivationInfo := &psbt.Bip32Derivation{
		// TODO(yy): get pubkey.
		// PubKey:               pubKey.SerializeCompressed(),
		MasterKeyFingerprint: deriv.MasterKeyFingerprint,
		Bip32Path: []uint32{
			deriv.KeyScope.Purpose,
			deriv.KeyScope.Coin,
			deriv.Account,
			deriv.Branch,
			deriv.Index,
		},
	}

	return derivationInfo, nil
}
