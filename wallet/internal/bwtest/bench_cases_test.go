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

// TestSyncBenchmarkCasesPlaceWalletMatches checks actual owned-match heights,
// distinguishing zero-history and empty-block controls from foreign parents.
func TestSyncBenchmarkCasesPlaceWalletMatches(t *testing.T) {
	t.Parallel()

	// Arrange: reference ownership comes from the unchanged lnd graph. Fixed
	// script bytes suffice because this test checks placement, not signing.
	workload := ListUnspentCases()[0]

	scripts := make([][]byte, workload.Addresses)
	for i := range scripts {
		scripts[i] = append(
			[]byte{txscript.OP_0, txscript.OP_DATA_20},
			make([]byte, 20)...,
		)
	}

	records := workload.Batch(1, scripts).Transactions
	tests := []struct {
		id      string
		blocks  int32
		noise   int
		matches int
		first   int32
		last    int32
		step    int32
	}{
		{
			id:      "smoke",
			blocks:  10,
			noise:   6000,
			matches: 1,
			first:   5,
			last:    5,
			step:    1,
		},
		{
			id:     "empty",
			blocks: 1000,
		},
		{
			id:     "hits-0",
			blocks: 1000,
			noise:  6000,
		},
		{
			id:      "hits-1",
			blocks:  1000,
			noise:   6000,
			matches: 1,
			first:   500,
			last:    500,
			step:    1,
		},
		{
			id:      "small-node",
			blocks:  1000,
			noise:   6000,
			matches: 10,
			first:   100,
			last:    1000,
			step:    100,
		},
		{
			id:      "hits-100",
			blocks:  1000,
			noise:   6000,
			matches: 100,
			first:   10,
			last:    1000,
			step:    10,
		},
		{
			id:     "payload-1",
			blocks: 1000,
			noise:  1,
		},
		{
			id:     "payload-100",
			blocks: 1000,
			noise:  100,
		},
	}

	// Act: obtain only the public case factory's schedules. Expectations above
	// state the requested experiment independently of its grouping algorithm.
	cases := SyncBenchmarkCases()

	// Assert: count blocks with owned credits, rather than treating foreign
	// force-close parents as Wallet hits. Ordered heights preserve ancestry.
	require.Len(t, cases, len(tests))

	for i, test := range tests {
		scenario := cases[i]
		require.Equal(t, test.id, scenario.ID)
		require.Equal(t, test.blocks, scenario.Blocks)
		require.Equal(t, test.noise, scenario.BackgroundTransactions)

		if test.matches == 0 {
			require.Empty(t, scenario.HistoryBlocks)
			continue
		}

		require.Len(t, scenario.HistoryBlocks, 204)

		matched := make(map[int32]bool)

		var previous int32
		for index, height := range scenario.HistoryBlocks {
			require.GreaterOrEqual(t, height, previous)
			require.Positive(t, height)
			require.LessOrEqual(t, height, scenario.Blocks)

			if len(records[index].Credits) != 0 {
				matched[height] = true
			}

			previous = height
		}

		require.Len(t, matched, test.matches)

		for height := test.first; height <= test.last; height += test.step {
			require.True(t, matched[height])
		}
	}
}

// TestSyncBackgroundBuildsValidSpends checks two successive real payment blocks
// so rolling change, independent lanes and valid signatures are exercised.
func TestSyncBackgroundBuildsValidSpends(t *testing.T) {
	t.Parallel()

	// Arrange: give three distinct coinbases to the same fixed preparation
	// miner. The small fan-out is a dependency, not the operation under test.
	addr, key, err := syncBenchmarkMinerAddress()
	require.NoError(t, err)

	defer key.Zero()

	script, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	var funding []*wire.MsgTx
	for height := byte(2); height <= 4; height++ {
		parent := wire.NewMsgTx(2)
		parent.AddTxIn(wire.NewTxIn(&wire.OutPoint{
			Index: ^uint32(0),
		}, []byte{1, height}, nil))
		parent.AddTxOut(wire.NewTxOut(5_000_000_000, script))
		funding = append(funding, parent)
	}

	fanout, err := BuildSyncBenchmarkFunding(funding, 3)
	require.NoError(t, err)

	// Act: build consecutive blocks through the public background builder,
	// passing only the prior block rather than a whole retained chain graph.
	first, err := BuildSyncBenchmarkBackground(
		t.Context(), []*wire.MsgTx{fanout},
	)
	require.NoError(t, err)
	second, err := BuildSyncBenchmarkBackground(t.Context(), first)
	require.NoError(t, err)

	// Assert: both blocks retain exactly three lanes. Every fan-out/payment
	// input must reference a known output, execute and conserve total value.
	require.Len(t, first, 3)
	require.Len(t, second, 3)

	prevouts := txscript.NewMultiPrevOutFetcher(nil)
	for _, parent := range funding {
		prevouts.AddPrevOut(
			wire.OutPoint{Hash: parent.TxHash()}, parent.TxOut[0],
		)
	}

	transactions := append([]*wire.MsgTx{fanout}, first...)

	transactions = append(transactions, second...)
	for _, tx := range transactions {
		hashes := txscript.NewTxSigHashes(tx, prevouts)

		var inputs, outputs int64
		for index, input := range tx.TxIn {
			output := prevouts.FetchPrevOutput(input.PreviousOutPoint)
			require.NotNil(t, output)
			engine, err := txscript.NewEngine(
				output.PkScript, tx, index, txscript.StandardVerifyFlags,
				nil, hashes, output.Value, prevouts,
			)
			require.NoError(t, err)
			require.NoError(t, engine.Execute())

			inputs += output.Value
		}

		for index, output := range tx.TxOut {
			require.Positive(t, output.Value)
			outputs += output.Value
			prevouts.AddPrevOut(wire.OutPoint{
				Hash: tx.TxHash(), Index: uint32(index),
			}, output)
		}

		require.Greater(t, inputs, outputs)
	}

	// Assert: removing a payment signature reproduces an invalid background
	// transaction; ancestry and plausible counts alone must not pass.
	unsigned := second[0].Copy()
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
