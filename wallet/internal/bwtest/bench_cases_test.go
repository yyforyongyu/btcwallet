package bwtest

import (
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// TestSyncHistoryBuildsValidSpends proves that the shared unsigned graph can
// become a valid spend chain, including both force-close ancestors and sweeps.
func TestSyncHistoryBuildsValidSpends(t *testing.T) {
	t.Parallel()

	// Arrange: use the existing smoke graph with known witness/Taproot keys.
	// Real preparation supplies the same ordinary script classes and actual
	// mined coinbases; this test isolates signatures and ancestry from mining.
	workload := ListUnspentCases()[3]

	key, pub := btcec.PrivKeyFromBytes([]byte{2})
	defer key.Zero()

	params := &chaincfg.RegressionNetParams
	receive, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pub.SerializeCompressed()), params,
	)
	require.NoError(t, err)
	miner, minerKey, err := syncBenchmarkMinerAddress()
	require.NoError(t, err)

	defer minerKey.Zero()

	change, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(pub)),
		params,
	)
	require.NoError(t, err)

	scripts := make([][]byte, workload.Addresses)
	for index := range scripts {
		scripts[index], err = txscript.PayToAddrScript(change)
		require.NoError(t, err)
	}

	scripts[0], err = txscript.PayToAddrScript(receive)
	require.NoError(t, err)
	minerScript, err := txscript.PayToAddrScript(miner)
	require.NoError(t, err)

	funding := wire.NewMsgTx(2)
	funding.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Index: ^uint32(0),
	}, []byte{1, 1}, nil))
	funding.AddTxOut(wire.NewTxOut(5_000_000_000, minerScript))

	// Act: replace synthetic funding and sign owned inputs through the same
	// narrow callback used by real Wallet preparation. Low-level signatures
	// here keep the test focused on graph assembly rather than Wallet setup.
	history, err := BuildSyncBenchmarkHistory(
		t.Context(), workload, scripts,
		[]*wire.MsgTx{funding}, func(_ context.Context, tx *wire.MsgTx,
			index int, output *wire.TxOut,
			hashes *txscript.TxSigHashes) (wire.TxWitness, error) {

			if txscript.IsPayToTaproot(output.PkScript) {
				return txscript.TaprootWitnessSignature(
					tx, hashes, index, output.Value, output.PkScript,
					txscript.SigHashDefault, key,
				)
			}

			return txscript.WitnessSignature(
				tx, hashes, index, output.Value, output.PkScript,
				txscript.SigHashAll, key, true,
			)
		},
	)
	require.NoError(t, err)

	// Assert: every input must already exist, conserve value and execute under
	// standard script flags. This includes the multi-parent mixed-input sweep.
	prevouts := txscript.NewMultiPrevOutFetcher(nil)
	prevouts.AddPrevOut(wire.OutPoint{Hash: funding.TxHash()}, funding.TxOut[0])

	contracts := make(map[string]bool)

	for _, tx := range history {
		hashes := txscript.NewTxSigHashes(tx, prevouts)

		var inputValue, outputValue int64
		for index, input := range tx.TxIn {
			output := prevouts.FetchPrevOutput(input.PreviousOutPoint)
			require.NotNil(t, output)
			engine, err := txscript.NewEngine(
				output.PkScript, tx, index,
				txscript.StandardVerifyFlags, nil, hashes, output.Value,
				prevouts,
			)
			require.NoError(t, err)
			require.NoError(t, engine.Execute())

			inputValue += output.Value
		}

		for index, output := range tx.TxOut {
			// Foreign outputs must retain distinct scripts; collapsing
			// them changes filter contents even if spends still validate.
			if txscript.IsPayToWitnessScriptHash(output.PkScript) {
				require.False(t, contracts[string(output.PkScript)])
				contracts[string(output.PkScript)] = true
			}

			outputValue += output.Value
			prevouts.AddPrevOut(wire.OutPoint{
				Hash: tx.TxHash(), Index: uint32(index),
			}, output)
		}

		require.GreaterOrEqual(t, inputValue, outputValue)
	}

	// Assert: restoring the old unsigned-input condition fails validation,
	// so a graph with correct counts alone cannot masquerade as chain-valid.
	unsigned := history[1].Copy()
	unsigned.TxIn[0].Witness = nil
	output := prevouts.FetchPrevOutput(unsigned.TxIn[0].PreviousOutPoint)
	engine, err := txscript.NewEngine(
		output.PkScript, unsigned, 0,
		txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(unsigned, prevouts), output.Value, prevouts,
	)
	require.NoError(t, err)
	require.Error(t, engine.Execute())
}

// TestListUnspentWorkloadModelsReference checks replicated graphs against the
// observed one-deposit endpoint, including cross-unit outpoint separation.
func TestListUnspentWorkloadModelsReference(t *testing.T) {
	t.Parallel()

	// Arrange: expected endpoints are multiples of the saved lnd census;
	// the shared cases provide only inputs, never the expected graph totals.
	tests := []struct {
		funding      uint32
		transactions int
		utxos        int
		value        int64
	}{
		{
			funding:      1,
			transactions: 204,
			utxos:        101,
			value:        89_636_054,
		},
		{
			funding:      10,
			transactions: 2_040,
			utxos:        1_010,
			value:        896_360_540,
		},
		{
			funding:      100,
			transactions: 20_400,
			utxos:        10_100,
			value:        8_963_605_400,
		},
	}
	for index, test := range tests {
		// Arrange: supply distinct scripts in receiving/change/closing
		// order. Native seeders derive real addresses; this isolates
		// transaction ownership and graph links.
		workload := ListUnspentCases()[index]

		scripts := make([][]byte, workload.Addresses)
		for i := range scripts {
			material := []byte(fmt.Sprintf("reference-script/%d", i))

			hash := chainhash.DoubleHashH(material)
			if i < int(test.funding) {
				scripts[i] = append(
					[]byte{txscript.OP_0, txscript.OP_DATA_20},
					hash[:20]...,
				)
			} else {
				scripts[i] = append(
					[]byte{txscript.OP_1, txscript.OP_DATA_32},
					hash[:]...,
				)
			}
		}

		// Act: consume inputs before recording outputs to reconstruct
		// the graph. Tracking foreign outputs too detects missing
		// parents and repeated contract spends behind the totals.
		batch := workload.Batch(1, scripts)
		outputs := make(map[wire.OutPoint]*wire.TxOut)
		spent := make(map[wire.OutPoint]struct{})
		owned := make(map[wire.OutPoint]*wire.TxOut)

		externalRoots := 0
		for _, record := range batch.Transactions {
			for _, input := range record.Tx.TxIn {
				point := input.PreviousOutPoint
				if _, known := outputs[point]; !known {
					externalRoots++
				}

				_, duplicate := spent[point]
				require.False(t, duplicate)

				spent[point] = struct{}{}
				delete(owned, point)
			}

			hash := record.Tx.TxHash()
			for index, output := range record.Tx.TxOut {
				point := wire.OutPoint{
					Hash:  hash,
					Index: uint32(index),
				}
				_, duplicate := outputs[point]
				require.False(t, duplicate)

				outputs[point] = output
				if _, credit := record.Credits[uint32(index)]; credit {
					require.NotNil(t, record.Block)

					owned[point] = output
				}
			}
		}

		// Assert: scale the observed endpoint by deposits. Unique
		// outpoints ensure totals cannot pass by replaying one unit
		// or unintentionally consuming another unit's inputs.
		require.EqualValues(t, test.funding, externalRoots)
		require.Len(t, batch.Transactions, test.transactions)
		require.Len(t, owned, test.utxos)

		var value int64
		for _, output := range owned {
			require.True(t, txscript.IsPayToTaproot(output.PkScript))
			value += output.Value
		}

		require.Equal(t, test.value, value)
	}
}
