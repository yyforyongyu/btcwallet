// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"log"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

func rollback(ns walletdb.ReadWriteBucket, height int32) error {
	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}

	// Keep track of all credits that were removed from coinbase
	// transactions.  After detaching all blocks, if any transaction record
	// exists in unmined that spends these outputs, remove them and their
	// spend chains.
	//
	// It is necessary to keep these in memory and fix the unmined
	// transactions later since blocks are removed in increasing order.
	var coinBaseCredits []wire.OutPoint
	var heightsToRemove []int32

	it := makeReverseBlockIterator(ns)
	for it.prev() {
		b := &it.elem
		if it.elem.Height < height {
			break
		}

		heightsToRemove = append(heightsToRemove, it.elem.Height)

		log.Printf("Rolling back %d transactions from block %v height %d",
			len(b.Transactions), b.Hash, b.Height)

		for i := range b.Transactions {
			txHash := &b.Transactions[i]

			recKey := keyTxRecord(txHash, &b.Block)
			recVal := existsRawTxRecord(ns, recKey)
			var rec wtxmgr.TxRecord
			err = readRawTxRecord(txHash, recVal, &rec)
			if err != nil {
				return err
			}

			err = deleteTxRecord(ns, txHash, &b.Block)
			if err != nil {
				return err
			}

			// Handle coinbase transactions specially since they are
			// not moved to the unconfirmed store.  A coinbase cannot
			// contain any debits, but all credits should be removed
			// and the mined balance decremented.
			if blockchain.IsCoinBaseTx(&rec.MsgTx) {
				op := wire.OutPoint{Hash: rec.Hash}
				for i, output := range rec.MsgTx.TxOut {
					k, v := existsCredit(ns, &rec.Hash,
						uint32(i), &b.Block)
					if v == nil {
						continue
					}
					op.Index = uint32(i)

					coinBaseCredits = append(coinBaseCredits, op)

					unspentKey, credKey := existsUnspent(ns, &op)
					if credKey != nil {
						minedBalance -= btcutil.Amount(output.Value)
						err = deleteRawUnspent(ns, unspentKey)
						if err != nil {
							return err
						}
					}
					err = deleteRawCredit(ns, k)
					if err != nil {
						return err
					}
				}

				continue
			}

			err = putRawUnmined(ns, txHash[:], recVal)
			if err != nil {
				return err
			}

			// For each debit recorded for this transaction, mark
			// the credit it spends as unspent (as long as it still
			// exists) and delete the debit.  The previous output is
			// recorded in the unconfirmed store for every previous
			// output, not just debits.
			for i, input := range rec.MsgTx.TxIn {
				prevOut := &input.PreviousOutPoint
				prevOutKey := wtxmgr.CanonicalOutPoint(&prevOut.Hash,
					prevOut.Index)
				err = putRawUnminedInput(ns, prevOutKey, rec.Hash[:])
				if err != nil {
					return err
				}

				// If this input is a debit, remove the debit
				// record and mark the credit that it spent as
				// unspent, incrementing the mined balance.
				debKey, credKey, err := existsDebit(ns,
					&rec.Hash, uint32(i), &b.Block)
				if err != nil {
					return err
				}
				if debKey == nil {
					continue
				}

				// unspendRawCredit does not error in case the
				// no credit exists for this key, but this
				// behavior is correct.  Since blocks are
				// removed in increasing order, this credit
				// may have already been removed from a
				// previously removed transaction record in
				// this rollback.
				var amt btcutil.Amount
				amt, err = unspendRawCredit(ns, credKey)
				if err != nil {
					return err
				}
				err = deleteRawDebit(ns, debKey)
				if err != nil {
					return err
				}

				// If the credit was previously removed in the
				// rollback, the credit amount is zero.  Only
				// mark the previously spent credit as unspent
				// if it still exists.
				if amt == 0 {
					continue
				}
				unspentVal, err := fetchRawCreditUnspentValue(credKey)
				if err != nil {
					return err
				}
				minedBalance += amt
				err = putRawUnspent(ns, prevOutKey, unspentVal)
				if err != nil {
					return err
				}
			}

			// For each detached non-coinbase credit, move the
			// credit output to unmined.  If the credit is marked
			// unspent, it is removed from the utxo set and the
			// mined balance is decremented.
			//
			// TODO: use a credit iterator
			for i, output := range rec.MsgTx.TxOut {
				k, v := existsCredit(ns, &rec.Hash, uint32(i),
					&b.Block)
				if v == nil {
					continue
				}

				amt, change, err := fetchRawCreditAmountChange(v)
				if err != nil {
					return err
				}
				outPointKey := wtxmgr.CanonicalOutPoint(&rec.Hash, uint32(i))
				unminedCredVal := wtxmgr.ValueUnminedCredit(amt, change)
				err = putRawUnminedCredit(ns, outPointKey, unminedCredVal)
				if err != nil {
					return err
				}

				err = deleteRawCredit(ns, k)
				if err != nil {
					return err
				}

				credKey := existsRawUnspent(ns, outPointKey)
				if credKey != nil {
					minedBalance -= btcutil.Amount(output.Value)
					err = deleteRawUnspent(ns, outPointKey)
					if err != nil {
						return err
					}
				}
			}
		}

		// reposition cursor before deleting this k/v pair and advancing to the
		// previous.
		it.reposition(it.elem.Height)

		// Avoid cursor deletion until bolt issue #620 is resolved.
		// err = it.delete()
		// if err != nil {
		// 	return err
		// }
	}
	if it.err != nil {
		return it.err
	}

	// Delete the block records outside of the iteration since cursor deletion
	// is broken.
	for _, h := range heightsToRemove {
		err = deleteBlockRecord(ns, h)
		if err != nil {
			return err
		}
	}

	for _, op := range coinBaseCredits {
		opKey := wtxmgr.CanonicalOutPoint(&op.Hash, op.Index)
		unminedSpendTxHashKeys := fetchUnminedInputSpendTxHashes(ns, opKey)
		for _, unminedSpendTxHashKey := range unminedSpendTxHashKeys {
			unminedVal := existsRawUnmined(ns, unminedSpendTxHashKey[:])

			// If the spending transaction spends multiple outputs
			// from the same transaction, we'll find duplicate
			// entries within the store, so it's possible we're
			// unable to find it if the conflicts have already been
			// removed in a previous iteration.
			if unminedVal == nil {
				continue
			}

			var unminedRec wtxmgr.TxRecord
			unminedRec.Hash = unminedSpendTxHashKey
			err = readRawTxRecord(&unminedRec.Hash, unminedVal, &unminedRec)
			if err != nil {
				return err
			}

			log.Printf("Transaction %v spends a removed coinbase "+
				"output -- removing as well", unminedRec.Hash)
			err = removeConflict(ns, &unminedRec)
			if err != nil {
				return err
			}
		}
	}

	return putMinedBalance(ns, minedBalance)
}
