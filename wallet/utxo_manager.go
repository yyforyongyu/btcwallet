// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet provides a bitcoin wallet implementation that is centered
// around the concept of a UtxoManager, which is responsible for managing the
// wallet's UTXO set.
//
//nolint:wrapcheck
package wallet

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	errUtxoHeightOverflow  = errors.New("utxo height overflows int32")
	errUnsupportedAddrType = errors.New("unsupported address type")
)

// Utxo provides a detailed overview of an unspent transaction output.
type Utxo struct {
	// OutPoint is the transaction output identifier.
	OutPoint wire.OutPoint

	// Amount is the value of the output.
	Amount btcutil.Amount

	// PkScript is the public key script for the output.
	PkScript []byte

	// Confirmations is the number of confirmations the output has.
	Confirmations int32

	// Spendable indicates whether the output is considered spendable.
	Spendable bool

	// Address is the address associated with the output.
	Address btcutil.Address

	// Account is the name of the account that owns the output.
	Account string

	// AddressType is the type of the address.
	AddressType waddrmgr.AddressType

	// Locked indicates whether the output is locked.
	Locked bool
}

// LeasedOutput describes one currently leased wallet output.
type LeasedOutput struct {
	// OutPoint is the leased transaction output identifier.
	OutPoint wire.OutPoint

	// LockID is the lease owner identifier.
	LockID wtxmgr.LockID

	// Expiration is when the current lease expires.
	Expiration time.Time
}

// UtxoQuery holds the set of options for a ListUnspent query.
type UtxoQuery struct {
	// Account specifies the account to query UTXOs for. If empty,
	// UTXOs from all accounts are returned.
	Account string

	// MinConfs is the minimum number of confirmations a UTXO must have.
	MinConfs int32

	// MaxConfs is the maximum number of confirmations a UTXO can have.
	MaxConfs int32
}

// UtxoManager provides an interface for querying and managing the wallet's
// UTXO set.
type UtxoManager interface {
	// ListUnspent returns a slice of all unspent transaction outputs that
	// match the query. The returned UTXOs are sorted by amount in
	// ascending order.
	ListUnspent(ctx context.Context, query UtxoQuery) ([]*Utxo, error)

	// GetUtxo returns the output information for a given outpoint.
	GetUtxo(ctx context.Context, prevOut wire.OutPoint) (*Utxo, error)

	// LeaseOutput locks an output for a given duration, preventing it from
	// being used in transactions.
	LeaseOutput(ctx context.Context, id wtxmgr.LockID,
		op wire.OutPoint, duration time.Duration) (time.Time, error)

	// ReleaseOutput unlocks a previously leased output, making it available
	// for use.
	ReleaseOutput(ctx context.Context, id wtxmgr.LockID,
		op wire.OutPoint) error

	// ListLeasedOutputs returns a list of all currently leased outputs.
	ListLeasedOutputs(ctx context.Context) ([]*LeasedOutput, error)
}

// ListUnspent returns the wallet-owned UTXOs that match the provided query.
//
// TODO(yy): Collapse the SQL-backed ListUnspent path into one enriched store
// read by (1) extending ListUTXOs to return account, address type,
// spendable, and locked state, (2) having the SQL backends populate those
// fields from one joined query, and (3) removing the follow-up
// ListLeasedOutputs/GetAddressDetails composition here.
//
// NOTE: This is part of the UtxoManager interface implementation.
func (w *Wallet) ListUnspent(ctx context.Context,
	query UtxoQuery) ([]*Utxo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	log.Debugf("ListUnspent using query: %v", query)

	currentHeight := w.addrStore.SyncedTo().Height
	minConfs := query.MinConfs
	maxConfs := query.MaxConfs

	infos, err := w.store.ListUTXOs(ctx, db.ListUtxosQuery{
		WalletID: w.id,
		MinConfs: &minConfs,
		MaxConfs: &maxConfs,
		Account:  nil,
	})
	if err != nil {
		return nil, fmt.Errorf("list utxos: %w", err)
	}

	leases, err := w.store.ListLeasedOutputs(ctx, w.id)
	if err != nil {
		return nil, fmt.Errorf("list leased outputs: %w", err)
	}

	lockedOutputs := leasedOutputSet(leases)

	utxos := make([]*Utxo, 0, len(infos))
	for i := range infos {
		utxo, include, err := w.buildWalletUtxoFromStore(
			ctx, &infos[i], currentHeight, query.Account,
			lockedOutputs[infos[i].OutPoint],
		)
		if err != nil {
			return nil, err
		}

		if include {
			utxos = append(utxos, utxo)
		}
	}

	// Sort the outputs in ascending order of value. This is a convention
	// to make the list more predictable and potentially useful for coin
	// selection algorithms that prefer smaller UTXOs.
	sort.Slice(utxos, func(i, j int) bool {
		return utxos[i].Amount < utxos[j].Amount
	})

	return utxos, nil
}

// GetUtxo returns one wallet-owned UTXO together with its wallet-facing
// metadata.
//
// TODO(yy): Collapse the SQL-backed GetUtxo path into one enriched store read
// by (1) extending GetUtxo to return account, address type, spendable, and
// locked state, (2) having the SQL backends populate those fields from one
// joined query, and (3) removing the follow-up
// ListLeasedOutputs/GetAddressDetails composition here.
//
// NOTE: This is part of the UtxoManager interface implementation.
func (w *Wallet) GetUtxo(ctx context.Context,
	prevOut wire.OutPoint) (*Utxo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	currentHeight := w.addrStore.SyncedTo().Height

	info, err := w.store.GetUtxo(ctx, db.GetUtxoQuery{
		WalletID: w.id,
		OutPoint: prevOut,
	})
	if err != nil {
		if errors.Is(err, db.ErrUtxoNotFound) {
			return nil, wtxmgr.ErrUtxoNotFound
		}

		return nil, fmt.Errorf("get utxo: %w", err)
	}

	leases, err := w.store.ListLeasedOutputs(ctx, w.id)
	if err != nil {
		return nil, fmt.Errorf("list leased outputs: %w", err)
	}

	lockedOutputs := leasedOutputSet(leases)

	utxo, include, err := w.buildWalletUtxoFromStore(
		ctx, info, currentHeight, "", lockedOutputs[info.OutPoint],
	)
	if err != nil {
		return nil, err
	}

	if !include {
		return nil, wtxmgr.ErrUtxoNotFound
	}

	return utxo, nil
}

// buildWalletUtxoFromStore converts one store-level UTXO row into the wallet's
// public Utxo view.
func (w *Wallet) buildWalletUtxoFromStore(ctx context.Context,
	info *db.UtxoInfo, currentHeight int32,
	accountFilter string, locked bool) (*Utxo, bool, error) {

	addr := extractAddrFromPKScript(info.PkScript, w.cfg.ChainParams)
	if addr == nil {
		return nil, false, nil
	}

	spendable, account, addrType, err := w.lookupStoreAddressDetails(
		ctx, info.PkScript,
	)
	if err != nil {
		return nil, false, err
	}

	if accountFilter != "" && account != accountFilter {
		return nil, false, nil
	}

	confirmations, err := utxoConfirmations(info.Height, currentHeight)
	if err != nil {
		return nil, false, err
	}

	if info.FromCoinBase {
		maturity := w.cfg.ChainParams.CoinbaseMaturity
		if confirmations < int32(maturity) {
			spendable = false
		}
	}

	return &Utxo{
		OutPoint:      info.OutPoint,
		Amount:        info.Amount,
		PkScript:      info.PkScript,
		Confirmations: confirmations,
		Spendable:     spendable,
		Address:       addr,
		Account:       account,
		AddressType:   addrType,
		Locked:        locked,
	}, true, nil
}

// leasedOutputSet builds the active locked-outpoint set from one lease list.
func leasedOutputSet(leases []db.LeasedOutput) map[wire.OutPoint]bool {
	locked := make(map[wire.OutPoint]bool, len(leases))
	for i := range leases {
		locked[leases[i].OutPoint] = true
	}

	return locked
}

// lookupStoreAddressDetails resolves the wallet-facing address metadata for one
// UTXO script.
func (w *Wallet) lookupStoreAddressDetails(ctx context.Context,
	pkScript []byte) (bool, string, waddrmgr.AddressType, error) {

	spendable, account, addrType, err := w.store.GetAddressDetails(
		ctx, db.GetAddressDetailsQuery{
			WalletID:     w.id,
			ScriptPubKey: pkScript,
		},
	)
	if err != nil {
		return false, "", 0, fmt.Errorf("get address details: %w", err)
	}

	walletAddrType, err := walletAddressType(addrType)
	if err != nil {
		return false, "", 0, err
	}

	return spendable, account, walletAddrType, nil
}

// utxoConfirmations converts one db-native UTXO height into wallet
// confirmation semantics.
func utxoConfirmations(height uint32, currentHeight int32) (int32, error) {
	if height == db.UnminedHeight {
		return 0, nil
	}

	txHeight, ok := safeUint32ToInt32(height)
	if !ok {
		return 0, fmt.Errorf("%w: %d", errUtxoHeightOverflow, height)
	}

	return calcConf(txHeight, currentHeight), nil
}

// walletAddressType maps one db-native address type into the legacy wallet
// address type enum used by the public UTXO view.
func walletAddressType(addrType db.AddressType) (waddrmgr.AddressType, error) {
	switch addrType {
	case db.RawPubKey:
		return waddrmgr.RawPubKey, nil
	case db.PubKeyHash:
		return waddrmgr.PubKeyHash, nil
	case db.ScriptHash:
		return waddrmgr.Script, nil
	case db.NestedWitnessPubKey:
		return waddrmgr.NestedWitnessPubKey, nil
	case db.WitnessPubKey:
		return waddrmgr.WitnessPubKey, nil
	case db.WitnessScript:
		return waddrmgr.WitnessScript, nil
	case db.TaprootPubKey:
		return waddrmgr.TaprootPubKey, nil
	case db.Anchor:
		return 0, fmt.Errorf("%w: %v", errUnsupportedAddrType, addrType)
	default:
		return 0, fmt.Errorf("%w: %v", errUnsupportedAddrType, addrType)
	}
}

// LeaseOutput locks one wallet output for the given duration.
//
// NOTE: This is part of the UtxoManager interface implementation.
func (w *Wallet) LeaseOutput(ctx context.Context, id wtxmgr.LockID,
	op wire.OutPoint, duration time.Duration) (time.Time, error) {

	err := w.state.validateStarted()
	if err != nil {
		return time.Time{}, err
	}

	lease, err := w.store.LeaseOutput(ctx, db.LeaseOutputParams{
		WalletID: w.id,
		ID:       db.LockID(id),
		OutPoint: op,
		Duration: duration,
	})
	if err != nil {
		switch {
		case errors.Is(err, db.ErrUtxoNotFound):
			return time.Time{}, wtxmgr.ErrUnknownOutput

		case errors.Is(err, db.ErrOutputAlreadyLeased):
			return time.Time{}, wtxmgr.ErrOutputAlreadyLocked
		}

		return time.Time{}, fmt.Errorf("lease output: %w", err)
	}

	return lease.Expiration, nil
}

// ReleaseOutput unlocks a previously leased output, making it available for
// coin selection again.
//
// The lock is released by delegating to the wallet's db.Store implementation.
func (w *Wallet) ReleaseOutput(ctx context.Context, id wtxmgr.LockID,
	op wire.OutPoint) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	params := db.ReleaseOutputParams{
		WalletID: w.id,
		ID:       [32]byte(id),
		OutPoint: op,
	}

	return w.store.ReleaseOutput(ctx, params)
}

// ListLeasedOutputs returns the wallet-owned outputs that currently have active
// leases.
//
// NOTE: This is part of the UtxoManager interface implementation.
func (w *Wallet) ListLeasedOutputs(
	ctx context.Context) ([]*LeasedOutput, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	leases, err := w.store.ListLeasedOutputs(ctx, w.id)
	if err != nil {
		return nil, fmt.Errorf("list leased outputs: %w", err)
	}

	outputs := make([]*LeasedOutput, len(leases))
	for i := range leases {
		outputs[i] = &LeasedOutput{
			OutPoint:   leases[i].OutPoint,
			LockID:     wtxmgr.LockID(leases[i].LockID),
			Expiration: leases[i].Expiration,
		}
	}

	return outputs, nil
}
