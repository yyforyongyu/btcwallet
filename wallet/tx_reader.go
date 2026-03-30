// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// ErrTxNotFound is returned when a transaction is not found in the
	// store.
	ErrTxNotFound = errors.New("tx not found")
)

// TxQuery contains the parameters for querying one wallet transaction.
type TxQuery struct {
	// TxHash is the transaction hash to query.
	TxHash chainhash.Hash

	// IncludeDetails controls whether wallet-relative value, fee, inputs, and
	// outputs are populated.
	IncludeDetails bool
}

// TxListQuery contains the parameters for listing wallet transactions.
type TxListQuery struct {
	// StartHeight is the starting height in wallet tx-reader semantics.
	StartHeight int32

	// EndHeight is the ending height in wallet tx-reader semantics.
	EndHeight int32

	// IncludeDetails controls whether wallet-relative value, fee, inputs, and
	// outputs are populated for each result.
	IncludeDetails bool
}

// TxReader provides an interface for querying tx history.
type TxReader interface {
	// GetTx returns one wallet transaction view using the provided query.
	GetTx(ctx context.Context, query TxQuery) (*TxDetail, error)

	// ListTxns returns wallet transaction views over the provided range.
	ListTxns(ctx context.Context, query TxListQuery) (
		[]*TxDetail, error)
}

// A compile-time assertion to ensure that Wallet implements the TxReader
// interface.
var _ TxReader = (*Wallet)(nil)

type normalizedTxListQuery struct {
	confirmedStart uint32
	confirmedEnd   uint32
	reverse        bool
	includeUnmined bool
	unminedFirst   bool
	hasConfirmed   bool
}

const maxWalletTxHeight = uint32(math.MaxInt32)

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
	FeeRate btcunit.SatPerVByte

	// Weight is the tx's weight.
	Weight btcunit.WeightUnit

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

// GetTx returns a transaction view using the provided query.
//
// Time complexity: O(log n + I + O), where n is the number of
// transactions in the database, I is the number of inputs, and O is the
// number of outputs. The lookup is dominated by a key-based B-tree lookup
// in the database and the processing of the transaction's inputs and
// outputs.
func (w *Wallet) GetTx(ctx context.Context, query TxQuery) (
	*TxDetail, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	if !query.IncludeDetails {
		txInfo, err := w.store.GetTx(ctx, db.GetTxQuery{
			WalletID: w.id,
			Txid:     query.TxHash,
		})
		if err != nil {
			if errors.Is(err, db.ErrTxNotFound) {
				return nil, ErrTxNotFound
			}

			return nil, fmt.Errorf("get tx summary: %w", err)
		}

		currentHeight := w.SyncedTo().Height

		return w.buildTxSummary(txInfo, currentHeight)
	}

	txDetails, err := w.store.GetTxDetail(ctx, db.GetTxDetailQuery{
		WalletID: w.id,
		Txid:     query.TxHash,
	})
	if err != nil {
		if errors.Is(err, db.ErrTxNotFound) {
			return nil, ErrTxNotFound
		}

		return nil, fmt.Errorf("get tx detail: %w", err)
	}

	bestBlock := w.SyncedTo()
	currentHeight := bestBlock.Height

	return w.buildTxDetailFromStore(txDetails, currentHeight)
}

// ListTxns returns transaction views over the provided block range query.
//
// The underlying transaction store allows for reverse iteration, so if
// StartHeight > EndHeight, the transactions will be returned in reverse
// order.
//
// The special height -1 may be used to include unmined transactions. For
// example, to get all transactions from block 100 to the current tip including
// unmined, use a StartHeight of 100 and an EndHeight of -1. To get all
// transactions in the wallet, use a StartHeight of 0 and an EndHeight of -1.
//
// Time complexity: O(B + N), where B is the number of blocks in the
// range and N is the total number of inputs and outputs across all
// transactions in the range.
func (w *Wallet) ListTxns(ctx context.Context,
	query TxListQuery) ([]*TxDetail, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	currentHeight := w.SyncedTo().Height
	if query.IncludeDetails {
		var records []wtxmgr.TxDetails

		err = walletdb.View(w.cfg.DB, func(dbtx walletdb.ReadTx) error {
			txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

			err := w.txStore.RangeTransactions(
				txmgrNs, query.StartHeight, query.EndHeight,
				func(d []wtxmgr.TxDetails) (bool, error) {
					records = append(records, d...)

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

		details := make([]*TxDetail, 0, len(records))
		for _, detail := range records {
			txDetail := w.buildTxDetail(&detail, currentHeight)
			details = append(details, txDetail)
		}

		return details, nil
	}

	normalized := normalizeTxListQuery(query)

	var infos []db.TxInfo

	infos, err = w.appendUnminedTxSummariesIfNeeded(
		ctx,
		normalized.includeUnmined && normalized.unminedFirst,
		infos,
	)
	if err != nil {
		return nil, err
	}

	infos, err = w.appendConfirmedTxSummariesIfNeeded(
		ctx, normalized, infos,
	)
	if err != nil {
		return nil, err
	}

	infos, err = w.appendUnminedTxSummariesIfNeeded(
		ctx,
		normalized.includeUnmined && !normalized.unminedFirst,
		infos,
	)
	if err != nil {
		return nil, err
	}

	return w.buildTxSummaries(infos, currentHeight)
}

// appendUnminedTxSummariesIfNeeded appends the summary-store unmined view when
// the normalized wallet range requires it.
func (w *Wallet) appendUnminedTxSummariesIfNeeded(ctx context.Context,
	enabled bool, infos []db.TxInfo) ([]db.TxInfo, error) {

	if !enabled {
		return infos, nil
	}

	unmined, err := w.store.ListTxns(ctx, db.ListTxnsQuery{
		WalletID:    w.id,
		UnminedOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("list unmined tx summaries: %w", err)
	}

	return append(infos, unmined...), nil
}

// appendConfirmedTxSummariesIfNeeded appends the summary-store confirmed range
// view when the normalized wallet range requires it.
func (w *Wallet) appendConfirmedTxSummariesIfNeeded(ctx context.Context,
	normalized normalizedTxListQuery,
	infos []db.TxInfo) ([]db.TxInfo, error) {

	if !normalized.hasConfirmed {
		return infos, nil
	}

	confirmed, err := w.store.ListTxns(ctx, db.ListTxnsQuery{
		WalletID:    w.id,
		StartHeight: normalized.confirmedStart,
		EndHeight:   normalized.confirmedEnd,
	})
	if err != nil {
		return nil, fmt.Errorf("list confirmed tx summaries: %w", err)
	}

	if normalized.reverse {
		slices.Reverse(confirmed)
	}

	return append(infos, confirmed...), nil
}

// buildTxSummaries converts summary-store rows into wallet tx responses.
func (w *Wallet) buildTxSummaries(infos []db.TxInfo,
	currentHeight int32) ([]*TxDetail, error) {

	details := make([]*TxDetail, 0, len(infos))
	for i := range infos {
		txDetail, err := w.buildTxSummary(&infos[i], currentHeight)
		if err != nil {
			return nil, err
		}

		details = append(details, txDetail)
	}

	return details, nil
}

// normalizeTxListQuery converts wallet tx-reader range semantics into a simpler
// internal representation for summary-path query routing.
func normalizeTxListQuery(query TxListQuery) normalizedTxListQuery {
	switch {
	case query.StartHeight < 0 && query.EndHeight < 0:
		return normalizedTxListQuery{
			includeUnmined: true,
			unminedFirst:   true,
		}

	case query.StartHeight < 0:
		return normalizedTxListQuery{
			confirmedStart: nonNegativeHeightToUint32(query.EndHeight),
			confirmedEnd:   maxWalletTxHeight,
			reverse:        true,
			includeUnmined: true,
			unminedFirst:   true,
			hasConfirmed:   true,
		}

	case query.EndHeight < 0:
		return normalizedTxListQuery{
			confirmedStart: nonNegativeHeightToUint32(query.StartHeight),
			confirmedEnd:   maxWalletTxHeight,
			includeUnmined: true,
			hasConfirmed:   true,
		}

	default:
		start := query.StartHeight
		end := query.EndHeight

		reverse := start > end
		if reverse {
			start, end = end, start
		}

		return normalizedTxListQuery{
			confirmedStart: nonNegativeHeightToUint32(start),
			confirmedEnd:   nonNegativeHeightToUint32(end),
			reverse:        reverse,
			hasConfirmed:   true,
		}
	}
}

// nonNegativeHeightToUint32 converts a non-negative wallet tx-reader height to
// uint32.
func nonNegativeHeightToUint32(height int32) uint32 {
	if height < 0 {
		return 0
	}

	return uint32(height)
}

// fetchTxDetails fetches the tx details for the given tx hash
// from the wallet's tx store.
func (w *Wallet) fetchTxDetails(txHash *chainhash.Hash) (
	*wtxmgr.TxDetails, error) {

	var txDetails *wtxmgr.TxDetails

	err := walletdb.View(w.cfg.DB, func(dbtx walletdb.ReadTx) error {
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

	// TxDetails will return nil when the tx is not found.
	//
	// TODO(yy): We should instead return an error when the tx cannot be
	// found in the db.
	if txDetails == nil {
		return nil, ErrTxNotFound
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

// buildTxSummary builds a TxDetail from the given db-native transaction
// summary shape.
func (w *Wallet) buildTxSummary(txInfo *db.TxInfo,
	currentHeight int32) (*TxDetail, error) {

	msgTx, err := deserializeTxDetail(txInfo.SerializedTx)
	if err != nil {
		return nil, err
	}

	details := buildBasicTxDetail(
		txInfo.Hash, txInfo.SerializedTx, txInfo.Label, txInfo.Received, msgTx,
	)

	w.populateBlockDetailsFromBlock(details, txInfo.Block, currentHeight)

	return details, nil
}

// buildTxDetailFromStore builds a TxDetail from the given db-native detail
// shape returned by db.Store.
func (w *Wallet) buildTxDetailFromStore(txDetails *db.TxDetailInfo,
	currentHeight int32) (*TxDetail, error) {

	msgTx := txDetails.MsgTx
	if msgTx == nil {
		var err error

		msgTx, err = deserializeTxDetail(txDetails.SerializedTx)
		if err != nil {
			return nil, err
		}
	}

	details := w.buildBasicTxDetailFromStore(txDetails, msgTx)

	w.populateBlockDetailsFromStore(details, txDetails, currentHeight)
	w.calculateValueAndFeeFromStore(details, txDetails, msgTx)
	w.populateOutputsFromStore(details, txDetails, msgTx)
	w.populatePrevOutsFromStore(details, txDetails, msgTx)

	return details, nil
}

// buildBasicTxDetail builds the basic TxDetail from the given wtxmgr.TxDetails.
func (w *Wallet) buildBasicTxDetail(txDetails *wtxmgr.TxDetails) *TxDetail {
	return buildBasicTxDetail(
		txDetails.Hash, txDetails.SerializedTx, txDetails.Label,
		txDetails.Received, &txDetails.MsgTx,
	)
}

// buildBasicTxDetail builds the common non-wallet-relative fields for one tx
// response.
func buildBasicTxDetail(hash chainhash.Hash, rawTx []byte, label string,
	received time.Time, msgTx *wire.MsgTx) *TxDetail {

	txWeight := blockchain.GetTransactionWeight(
		btcutil.NewTx(msgTx),
	)

	return &TxDetail{
		Hash:         hash,
		RawTx:        rawTx,
		Label:        label,
		ReceivedTime: received,
		Weight:       safeInt64ToWeightUnit(txWeight),
		FeeRate:      btcunit.ZeroSatPerVByte,
	}
}

// buildBasicTxDetailFromStore builds the basic TxDetail from the given
// db-native detail shape.
func (w *Wallet) buildBasicTxDetailFromStore(txDetails *db.TxDetailInfo,
	msgTx *wire.MsgTx) *TxDetail {

	txWeight := blockchain.GetTransactionWeight(
		btcutil.NewTx(msgTx),
	)

	return &TxDetail{
		Hash:         txDetails.Hash,
		RawTx:        txDetails.SerializedTx,
		Label:        txDetails.Label,
		ReceivedTime: txDetails.Received,
		Weight:       safeInt64ToWeightUnit(txWeight),
		FeeRate:      btcunit.ZeroSatPerVByte,
	}
}

// populateBlockDetails populates the block details for the given TxDetail.
func (w *Wallet) populateBlockDetails(details *TxDetail,
	txDetails *wtxmgr.TxDetails, currentHeight int32) {
	w.populateBlockDetailsFromBlock(
		details,
		&db.Block{
			Hash:      txDetails.Block.Hash,
			Height:    nonNegativeHeight(txDetails.Block.Height),
			Timestamp: txDetails.Block.Time,
		},
		currentHeight,
	)

	if txDetails.Block.Height == -1 {
		details.Block = nil
		details.Confirmations = 0
	}
}

// populateBlockDetailsFromBlock populates the block details from a db-native
// block shape.
func (w *Wallet) populateBlockDetailsFromBlock(details *TxDetail,
	block *db.Block, currentHeight int32) {

	if block == nil {
		return
	}

	height, ok := safeUint32ToInt32(block.Height)
	if !ok {
		log.Warnf("Block height %d out of int32 range", block.Height)

		return
	}

	details.Block = &BlockDetails{
		Hash:      block.Hash,
		Height:    height,
		Timestamp: block.Timestamp.Unix(),
	}

	details.Confirmations = calcConf(height, currentHeight)
}

// populateBlockDetailsFromStore populates the block details for a store-backed
// TxDetail.
func (w *Wallet) populateBlockDetailsFromStore(details *TxDetail,
	txDetails *db.TxDetailInfo, currentHeight int32) {

	if txDetails.Block == nil {
		return
	}

	height, ok := safeUint32ToInt32(txDetails.Block.Height)
	if !ok {
		log.Warnf("Block height %d out of int32 range", txDetails.Block.Height)

		return
	}

	details.Block = &BlockDetails{
		Hash:      txDetails.Block.Hash,
		Height:    height,
		Timestamp: txDetails.Block.Timestamp.Unix(),
	}

	details.Confirmations = calcConf(height, currentHeight)
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

	// If not all inputs are ours, we can't calculate the total fee.
	// txDetails.Debits contains only our inputs, while
	// txDetails.MsgTx.TxIn contains all inputs. If they differ, some
	// inputs belong to external wallets and we don't know their input
	// values.
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
	details.FeeRate = btcunit.CalcSatPerVByte(
		details.Fee, details.Weight.ToVB(),
	)
}

// calculateValueAndFeeFromStore calculates the value and fee for the given
// store-backed TxDetail.
func (w *Wallet) calculateValueAndFeeFromStore(details *TxDetail,
	txDetails *db.TxDetailInfo, msgTx *wire.MsgTx) {

	var balanceDelta btcutil.Amount
	for _, debit := range txDetails.OwnedInputs {
		balanceDelta -= debit.Amount
	}

	for _, credit := range txDetails.OwnedOutputs {
		balanceDelta += credit.Amount
	}

	details.Value = balanceDelta

	if len(txDetails.OwnedInputs) != len(msgTx.TxIn) {
		return
	}

	var totalInput btcutil.Amount
	for _, debit := range txDetails.OwnedInputs {
		totalInput += debit.Amount
	}

	var totalOutput btcutil.Amount
	for _, txOut := range msgTx.TxOut {
		totalOutput += btcutil.Amount(txOut.Value)
	}

	details.Fee = totalInput - totalOutput
	details.FeeRate = btcunit.CalcSatPerVByte(
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
			txOut.PkScript, w.cfg.ChainParams,
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

// populateOutputsFromStore populates outputs for a store-backed TxDetail.
func (w *Wallet) populateOutputsFromStore(details *TxDetail,
	txDetails *db.TxDetailInfo, msgTx *wire.MsgTx) {

	isOurAddress := make(map[uint32]bool)
	for _, credit := range txDetails.OwnedOutputs {
		isOurAddress[credit.Index] = true
	}

	for i, txOut := range msgTx.TxOut {
		sc, outAddresses, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, w.cfg.ChainParams,
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

		details.Outputs = append(details.Outputs, Output{
			Type:      sc,
			Addresses: addresses,
			PkScript:  txOut.PkScript,
			Index:     i,
			Amount:    btcutil.Amount(txOut.Value),
			IsOurs:    isOurAddress[idx],
		})
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

// populatePrevOutsFromStore populates prevouts for a store-backed TxDetail.
func (w *Wallet) populatePrevOutsFromStore(details *TxDetail,
	txDetails *db.TxDetailInfo, msgTx *wire.MsgTx) {

	isOurOutput := make(map[uint32]bool)
	for _, debit := range txDetails.OwnedInputs {
		isOurOutput[debit.Index] = true
	}

	for i, txIn := range msgTx.TxIn {
		idx, ok := safeIntToUint32(i)
		if !ok {
			log.Warnf("Input index %d out of uint32 range", i)
			continue
		}

		details.PrevOuts = append(details.PrevOuts, PrevOut{
			OutPoint: txIn.PreviousOutPoint,
			IsOurs:   isOurOutput[idx],
		})
	}
}

// safeInt64ToWeightUnit converts an int64 to a unit.WeightUnit, ensuring the
// value is non-negative.
func safeInt64ToWeightUnit(w int64) btcunit.WeightUnit {
	if w < 0 {
		return btcunit.NewWeightUnit(0)
	}

	return btcunit.NewWeightUnit(uint64(w))
}

// safeIntToUint32 converts an int to a uint32, returning false if the
// conversion would overflow.
func safeIntToUint32(i int) (uint32, bool) {
	if i < 0 || i > math.MaxUint32 {
		return 0, false
	}

	return uint32(i), true
}

// safeUint32ToInt32 converts a uint32 to an int32, returning false if the
// conversion would overflow.
func safeUint32ToInt32(u uint32) (int32, bool) {
	if u > math.MaxInt32 {
		return 0, false
	}

	return int32(u), true
}

// deserializeTxDetail decodes a serialized transaction detail payload into a
// wire transaction when the store did not already provide a decoded MsgTx.
func deserializeTxDetail(rawTx []byte) (*wire.MsgTx, error) {
	var tx wire.MsgTx

	err := tx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		return nil, fmt.Errorf("deserialize tx detail: %w", err)
	}

	return &tx, nil
}

// nonNegativeHeight converts a legacy height into a uint32 for db-native block
// metadata.
func nonNegativeHeight(height int32) uint32 {
	if height < 0 {
		return 0
	}

	return uint32(height)
}
