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

	// IncludeDetails controls whether wallet-relative inputs, outputs, value,
	// and fee data are populated.
	//
	// When false, TxReader uses the summary store path and leaves those detail
	// fields at their zero values.
	IncludeDetails bool
}

// TxListQuery contains the parameters for listing wallet transactions.
type TxListQuery struct {
	// StartHeight is the starting height in wallet tx-reader semantics.
	StartHeight int32

	// EndHeight is the ending height in wallet tx-reader semantics.
	EndHeight int32

	// IncludeDetails controls whether wallet-relative inputs, outputs, value,
	// and fee data are populated for each returned transaction.
	IncludeDetails bool
}

// TxReader provides an interface for querying tx history.
type TxReader interface {
	// GetTx returns one transaction view using the requested query mode.
	GetTx(ctx context.Context, query TxQuery) (*TxDetail, error)

	// ListTxns returns transaction views over a block range using the requested
	// query mode.
	ListTxns(ctx context.Context, query TxListQuery) (
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

// GetTx returns one transaction view using either the summary or the detailed
// store path, depending on IncludeDetails.
//
// NOTE: This method is part of the TxReader interface.
func (w *Wallet) GetTx(ctx context.Context, query TxQuery) (
	*TxDetail, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	currentHeight := w.SyncedTo().Height
	if query.IncludeDetails {
		return w.getTxDetail(ctx, query, currentHeight)
	}

	return w.getTxSummary(ctx, query, currentHeight)
}

// ListTxns returns transaction views over a block range using either the
// summary or the detailed store path, depending on IncludeDetails.
//
// NOTE: This method is part of the TxReader interface.
func (w *Wallet) ListTxns(ctx context.Context, query TxListQuery) (
	[]*TxDetail, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	currentHeight := w.SyncedTo().Height
	if query.IncludeDetails {
		return w.listTxDetails(ctx, query, currentHeight)
	}

	return w.listTxSummaries(ctx, query, currentHeight)
}

type normalizedTxListQuery struct {
	confirmedStart uint32
	confirmedEnd   uint32
	reverse        bool
	includeUnmined bool
	unminedFirst   bool
	hasConfirmed   bool
}

const maxWalletTxHeight = uint32(math.MaxInt32)

// getTxSummary loads one transaction through the summary store path and builds
// the lightweight wallet response.
func (w *Wallet) getTxSummary(ctx context.Context, query TxQuery,
	currentHeight int32) (*TxDetail, error) {

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

	return w.buildTxSummary(txInfo, currentHeight)
}

// getTxDetail loads one transaction through the detailed store path and builds
// the full wallet response.
func (w *Wallet) getTxDetail(ctx context.Context, query TxQuery,
	currentHeight int32) (*TxDetail, error) {

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

	return w.buildTxDetailFromStore(txDetails, currentHeight)
}

// listTxSummaries loads transaction summaries over the requested wallet range
// and builds lightweight wallet responses.
func (w *Wallet) listTxSummaries(ctx context.Context, query TxListQuery,
	currentHeight int32) ([]*TxDetail, error) {

	normalized := normalizeTxListQuery(query)

	var infos []db.TxInfo

	infos, err := w.appendUnminedTxSummariesIfNeeded(
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

// listTxDetails loads detailed transactions over the requested wallet range and
// builds full wallet responses.
func (w *Wallet) listTxDetails(ctx context.Context, query TxListQuery,
	currentHeight int32) ([]*TxDetail, error) {

	records, err := w.store.ListTxDetails(ctx, db.ListTxDetailsQuery{
		WalletID:    w.id,
		StartHeight: query.StartHeight,
		EndHeight:   query.EndHeight,
	})
	if err != nil {
		return nil, fmt.Errorf("list tx details: %w", err)
	}

	details := make([]*TxDetail, 0, len(records))
	for i := range records {
		txDetail, err := w.buildTxDetailFromStore(&records[i], currentHeight)
		if err != nil {
			return nil, err
		}

		details = append(details, txDetail)
	}

	return details, nil
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
	value, ok := safeIntToUint32(int(height))
	if !ok {
		return 0
	}

	return value
}

// buildTxSummary builds a wallet tx response from the db-native summary shape.
func (w *Wallet) buildTxSummary(txInfo *db.TxInfo,
	currentHeight int32) (*TxDetail, error) {

	msgTx, err := deserializeTxDetail(txInfo.SerializedTx)
	if err != nil {
		return nil, err
	}

	details := buildBasicTxDetail(
		txInfo.Hash, txInfo.SerializedTx, txInfo.Label, txInfo.Received, msgTx,
	)

	w.populateBlockDetails(details, txInfo.Block, currentHeight)

	return details, nil
}

// buildTxDetailFromStore builds a wallet tx response from the db-native detail
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

	details := buildBasicTxDetail(
		txDetails.Hash, txDetails.SerializedTx, txDetails.Label,
		txDetails.Received, msgTx,
	)

	w.populateBlockDetails(details, txDetails.Block, currentHeight)
	w.calculateValueAndFeeFromStore(details, txDetails, msgTx)
	w.populateOutputs(details, msgTx, txDetails.OwnedOutputs)
	w.populatePrevOuts(details, msgTx, txDetails.OwnedInputs)

	return details, nil
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

// populateBlockDetails populates the block details for the given TxDetail.
func (w *Wallet) populateBlockDetails(details *TxDetail, block *db.Block,
	currentHeight int32) {

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

// populateOutputs populates outputs for a store-backed TxDetail.
func (w *Wallet) populateOutputs(details *TxDetail, msgTx *wire.MsgTx,
	ownedOutputs []db.TxOwnedOutput) {

	isOurAddress := make(map[uint32]bool)
	for _, credit := range ownedOutputs {
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

// populatePrevOuts populates prevouts for a store-backed TxDetail.
func (w *Wallet) populatePrevOuts(details *TxDetail, msgTx *wire.MsgTx,
	ownedInputs []db.TxOwnedInput) {

	isOurOutput := make(map[uint32]bool)
	for _, debit := range ownedInputs {
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
