// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/unit"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// ErrTxNotFound is returned when a transaction is not found in the
	// store.
	ErrTxNotFound = errors.New("tx not found")
)

// TxReader provides an interface for querying tx history.
type TxReader interface {
	// GetTx returns a detailed description of a tx given its tx hash.
	GetTx(ctx context.Context, txHash chainhash.Hash) (
		*TxDetail, error)

	// ListTxns returns a list of all txns which are relevant to the wallet
	// over a given block range.
	ListTxns(ctx context.Context, startHeight, endHeight int32) (
		[]*TxDetail, error)
}

// A compile-time assertion to ensure that Wallet implements the TxReader
// interface.
var _ TxReader = (*Wallet)(nil)

// Output contains details for a tx output.
type Output struct {
	// Addresses are the addresses associated with the output script.
	Addresses []btcutil.Address

	// PkScript is the raw output script.
	PkScript []byte

	// Index is the index of the output in the tx.
	Index int

	// Amount is the value of the output.
	Amount btcutil.Amount

	// Type is the script class of the output.
	Type txscript.ScriptClass

	// IsOurs is true if the output is controlled by the wallet.
	IsOurs bool
}

// PrevOut describes a tx input.
type PrevOut struct {
	// OutPoint is the unique reference to the output being spent.
	OutPoint wire.OutPoint

	// IsOurs is true if the input spends an output controlled by the
	// wallet.
	IsOurs bool
}

// BlockDetails contains details about the block that includes a tx.
type BlockDetails struct {
	// Hash is the hash of the block.
	Hash chainhash.Hash

	// Height is the height of the block.
	Height int32

	// Timestamp is the unix timestamp of the block.
	Timestamp int64
}

// TxDetail describes a tx relevant to a wallet. This is a flattened
// and information-dense structure designed to be returned by the TxReader
// interface.
type TxDetail struct {
	// Hash is the tx hash.
	Hash chainhash.Hash

	// RawTx is the serialized tx.
	RawTx []byte

	// Value is the net value of this tx (in satoshis) from the
	// POV of the wallet.
	Value btcutil.Amount

	// Fee is the total fee in satoshis paid by this tx.
	//
	// NOTE: This is only calculated if all inputs are known to the wallet.
	// Otherwise, it will be zero.
	//
	// TODO(yy): This should also be calculated for txns with external
	// inputs. This requires adding a `GetRawTransaction` method to the
	// `chain.Interface`.
	Fee btcutil.Amount

	// FeeRate is the fee rate of the tx in sat/vbyte.
	//
	// NOTE: This is only calculated if all inputs are known to the wallet.
	// Otherwise, it will be zero.
	FeeRate unit.SatPerVByte

	// Weight is the tx's weight.
	Weight unit.WeightUnit

	// Confirmations is the number of confirmations this tx has.
	// This will be 0 for unconfirmed txns.
	Confirmations int32

	// Block contains details of the block that includes this tx.
	Block *BlockDetails

	// ReceivedTime is the time the tx was received by the wallet.
	ReceivedTime time.Time

	// Outputs contains data for each tx output.
	Outputs []Output

	// PrevOuts are the inputs for the tx.
	PrevOuts []PrevOut

	// Label is an optional tx label.
	Label string
}

// GetTx returns a detailed description of a tx given its tx hash.
//
// NOTE: This method is part of the TxReader interface.
//
// Time complexity: O(1) amortized. The lookup is dominated by a key-based
// B-tree lookup in the database, which is effectively constant time for any
// realistic number of transactions.
func (w *Wallet) GetTx(_ context.Context, txHash chainhash.Hash) (
	*TxDetail, error) {

	txDetails, err := w.fetchTxDetails(&txHash)
	if err != nil {
		return nil, err
	}

	if txDetails == nil {
		return nil, ErrTxNotFound
	}

	bestBlock := w.SyncedTo()
	currentHeight := bestBlock.Height

	return w.buildTxDetail(txDetails, currentHeight), nil
}

// ListTxns returns a list of all txns which are relevant to the
// wallet over a given block range.
//
// NOTE: This method is part of the TxReader interface.
//
// Time complexity: O(B + T), where B is the number of blocks in the range and T
// is the number of transactions in those blocks.
func (w *Wallet) ListTxns(_ context.Context, startHeight,
	endHeight int32) ([]*TxDetail, error) {

	bestBlock := w.SyncedTo()
	currentHeight := bestBlock.Height

	var details []*TxDetail

	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		err := w.txStore.RangeTransactions(
			txmgrNs, startHeight, endHeight,
			func(d []wtxmgr.TxDetails) (bool, error) {
				for i := range d {
					detail := &d[i]

					txDetail := w.buildTxDetail(
						detail, currentHeight,
					)
					details = append(details, txDetail)
				}

				return false, nil
			},
		)
		if err != nil {
			return fmt.Errorf("tx range failed: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to view wallet db: %w", err)
	}

	return details, nil
}

// fetchTxDetails fetches the tx details for the given tx hash
// from the wallet's tx store.
func (w *Wallet) fetchTxDetails(txHash *chainhash.Hash) (
	*wtxmgr.TxDetails, error) {

	var txDetails *wtxmgr.TxDetails

	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		var err error

		txDetails, err = w.txStore.TxDetails(txmgrNs, txHash)
		if err != nil {
			return fmt.Errorf("failed to fetch tx details: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to view wallet db: %w", err)
	}

	return txDetails, nil
}

// buildTxDetail builds a TxDetail from the given wtxmgr.TxDetails.
func (w *Wallet) buildTxDetail(txDetails *wtxmgr.TxDetails,
	currentHeight int32) *TxDetail {

	details := w.buildBasicTxDetail(txDetails)

	w.populateBlockDetails(details, txDetails, currentHeight)
	w.calculateValueAndFee(details, txDetails)
	w.populateOutputs(details, txDetails)
	w.populatePrevOuts(details, txDetails)

	return details
}

// buildBasicTxDetail builds the basic TxDetail from the given wtxmgr.TxDetails.
func (w *Wallet) buildBasicTxDetail(txDetails *wtxmgr.TxDetails) *TxDetail {
	txWeight := blockchain.GetTransactionWeight(
		btcutil.NewTx(&txDetails.MsgTx),
	)

	return &TxDetail{
		Hash:         txDetails.Hash,
		RawTx:        txDetails.SerializedTx,
		Label:        txDetails.Label,
		ReceivedTime: txDetails.Received,
		Weight:       safeInt64ToWeightUnit(txWeight),
		FeeRate:      unit.SatPerVByte{Rat: big.NewRat(0, 1)},
	}
}

// populateBlockDetails populates the block details for the given TxDetail.
func (w *Wallet) populateBlockDetails(details *TxDetail,
	txDetails *wtxmgr.TxDetails, currentHeight int32) {

	height := txDetails.Block.Height
	if height == -1 {
		return
	}

	details.Block = &BlockDetails{
		Hash:      txDetails.Block.Hash,
		Height:    txDetails.Block.Height,
		Timestamp: txDetails.Block.Time.Unix(),
	}

	details.Confirmations = currentHeight - height + 1
}

// calculateValueAndFee calculates the value and fee for the given TxDetail.
func (w *Wallet) calculateValueAndFee(details *TxDetail,
	txDetails *wtxmgr.TxDetails) {

	var balanceDelta btcutil.Amount
	for _, debit := range txDetails.Debits {
		balanceDelta -= debit.Amount
	}

	for _, credit := range txDetails.Credits {
		balanceDelta += credit.Amount
	}

	details.Value = balanceDelta

	if len(txDetails.Debits) != len(txDetails.MsgTx.TxIn) {
		return
	}

	var totalInput btcutil.Amount
	for _, debit := range txDetails.Debits {
		totalInput += debit.Amount
	}

	var totalOutput btcutil.Amount
	for _, txOut := range txDetails.MsgTx.TxOut {
		totalOutput += btcutil.Amount(txOut.Value)
	}

	details.Fee = totalInput - totalOutput
	details.FeeRate = unit.NewSatPerVByte(
		details.Fee, details.Weight.ToVB(),
	)
}

// populateOutputs populates the outputs for the given TxDetail.
func (w *Wallet) populateOutputs(details *TxDetail,
	txDetails *wtxmgr.TxDetails) {

	isOurAddress := make(map[uint32]bool)
	for _, credit := range txDetails.Credits {
		isOurAddress[credit.Index] = true
	}

	for i, txOut := range txDetails.MsgTx.TxOut {
		sc, outAddresses, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, w.chainParams,
		)

		var addresses []btcutil.Address
		if err != nil {
			log.Warnf("Cannot extract addresses from pkScript for "+
				"tx %v, output %d: %v", details.Hash, i, err)
		} else {
			addresses = outAddresses
		}

		idx, ok := safeIntToUint32(i)
		if !ok {
			log.Warnf("Output index %d out of uint32 range", i)
			continue
		}

		details.Outputs = append(
			details.Outputs, Output{
				Type:      sc,
				Addresses: addresses,
				PkScript:  txOut.PkScript,
				Index:     i,
				Amount:    btcutil.Amount(txOut.Value),
				IsOurs:    isOurAddress[idx],
			},
		)
	}
}

// populatePrevOuts populates the previous outputs for the given TxDetail.
func (w *Wallet) populatePrevOuts(details *TxDetail,
	txDetails *wtxmgr.TxDetails) {

	isOurOutput := make(map[uint32]bool)
	for _, debit := range txDetails.Debits {
		isOurOutput[debit.Index] = true
	}

	for i, txIn := range txDetails.MsgTx.TxIn {
		idx, ok := safeIntToUint32(i)
		if !ok {
			log.Warnf("Input index %d out of uint32 range", i)
			continue
		}

		details.PrevOuts = append(
			details.PrevOuts, PrevOut{
				OutPoint: txIn.PreviousOutPoint,
				IsOurs:   isOurOutput[idx],
			},
		)
	}
}

// safeInt64ToWeightUnit converts an int64 to a unit.WeightUnit, ensuring the
// value is non-negative.
func safeInt64ToWeightUnit(w int64) unit.WeightUnit {
	if w < 0 {
		return 0
	}

	return unit.WeightUnit(w)
}

// safeIntToUint32 converts an int to a uint32, returning false if the
// conversion would overflow.
func safeIntToUint32(i int) (uint32, bool) {
	if i < 0 || i > math.MaxUint32 {
		return 0, false
	}

	return uint32(i), true
}
