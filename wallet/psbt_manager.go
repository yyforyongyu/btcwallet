// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// FundIntent represents the user's intent for funding a PSBT. It serves as
// a blueprint for the FundPsbt method, bundling all the parameters required
// to construct a funded transaction into a single, coherent structure.
type FundIntent struct {
	// MinConfs specifies the minimum number of confirmations a UTXO
	// must have to be included in the transaction.
	MinConfs int32

	// FeeRate specifies the desired fee rate for the transaction, expressed
	// in satoshis per kilo-virtual-byte (sat/kvb).
	FeeRate SatPerKVByte

	// FundSource specifies the account from which to select coins.
	FundSource *ScopedAccount

	// ChangeSource specifies the account to which the change output
	// should be sent. If nil, a change address will be derived from the
	// FundSource account.
	ChangeSource *ScopedAccount

	// Strategy is the coin selection algorithm to use. If nil, the wallet's
	// default strategy will be used.
	Strategy CoinSelectionStrategy

	// CandidateUTXOs provides an optional list of UTXOs that the coin
	// selection algorithm is restricted to choose from. This enables
	// "coin control". If nil or empty, the wallet will select from all
	// available UTXOs in the account.
	CandidateUTXOs []wire.OutPoint
}

// PsbtManager provides a cohesive, high-level interface for creating and
// managing Partially Signed Bitcoin Transactions (PSBTs). It encapsulates the
// entire workflow, from funding and decorating to signing and finalization,
// allowing users to construct complex transactions in a safe and predictable
// manner.
//
// The typical workflow for a single-signer transaction is as follows:
//
// 1. Create a bare PSBT:
// A stateless helper function, CreatePsbt, is used to construct a PSBT
// packet from a list of desired inputs and outputs.
//
//	// The user specifies their desired outputs.
//	outputs := []*wire.TxOut{{Value: 100000, PkScript: carolPkScript}}
//
//	// A bare PSBT is created, representing the transaction template.
//	packet, err := wallet.CreatePsbt(nil, outputs)
//
// 2. Fund the PSBT:
// The FundPsbt method is called to perform coin selection. The wallet selects
// UTXOs to cover the output value and fee, adds them as inputs, and adds a
// change output if necessary.
//
//	intent := &wallet.FundIntent{
//	    MinConfs: 1,
//	    FeeRate:  wallet.SatPerKVByte(10000),
//	    FundSource: &wallet.ScopedAccount{
//	        AccountName: "default",
//	        KeyScope:    waddrmgr.KeyScopeBIP0086,
//	    },
//	}
//	_, err = psbtManager.FundPsbt(ctx, packet, intent)
//
// 3. Sign the PSBT:
// The wallet signs all inputs it has the keys for.
//
//	err = psbtManager.SignPsbt(ctx, packet)
//
// 4. Finalize the PSBT:
// The final scriptSig and/or witness for each input is constructed.
//
//	err = psbtManager.FinalizePsbt(ctx, packet)
//
// 5. Extract and Broadcast:
// The final, network-ready transaction is extracted and broadcast.
//
//	finalTx, err := psbt.Extract(packet)
//	err = broadcaster.Broadcast(ctx, finalTx, "payment")
//
// For more detailed examples, including multi-party collaborative workflows,
// see the documentation in the `wallet/docs/psbt_workflows.md` file.
type PsbtManager interface {
	// FundPsbt adds inputs from the wallet and a change output to a PSBT
	// based on the provided intent. If the PSBT already contains inputs,
	// this method will act in "completion" mode, adding a change output
	// if necessary, but without performing coin selection.
	FundPsbt(ctx context.Context, packet *psbt.Packet,
		intent *FundIntent) (int32, error)

	// SignPsbt inspects the PSBT and adds a partial signature for every
	// input that it can sign. This method does not finalize the input.
	// It is the caller's responsibility to ensure the PSBT has all
	// necessary UTXO and script information.
	SignPsbt(ctx context.Context, packet *psbt.Packet) error

	// FinalizePsbt inspects the PSBT and, if all inputs are fully signed,
	// generates the final scriptSig and/or witness for each input and
	// clears the partial signature data.
	FinalizePsbt(ctx context.Context, packet *psbt.Packet) error

	// DecorateInputs adds UTXO and derivation information from the wallet
	// to a PSBT's inputs. This is useful when a PSBT is created
	// externally with only txids and output indices for its inputs.
	DecorateInputs(ctx context.Context, packet *psbt.Packet,
		failOnUnknown bool) error

	// CombinePsbt merges multiple PSBTs into one. This is essential for
	// multi-sig workflows where partial signatures are collected from
	// different signers.
	CombinePsbt(ctx context.Context, psbts ...*psbt.Packet) (
		*psbt.Packet, error)
}
