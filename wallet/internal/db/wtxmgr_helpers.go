// Copyright (c) 2015 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	byteOrder = binary.BigEndian

	bucketBlocks         = []byte("b")
	bucketTxRecords      = []byte("t")
	bucketCredits        = []byte("c")
	bucketUnspent        = []byte("u")
	bucketDebits         = []byte("d")
	bucketUnminedInputs  = []byte("mi")
	bucketLockedOutputs  = []byte("lo")

	rootMinedBalance = []byte("bal")
)

var ErrData = wtxmgr.Error{
	Code: wtxmgr.ErrData,
}

func storeError(code wtxmgr.ErrorCode, str string, err error) error {
	return wtxmgr.Error{
		Code: code,
		Err:  err,
	}
}

func fetchMinedBalance(ns walletdb.ReadBucket) (btcutil.Amount, error) {
	v := ns.Get(rootMinedBalance)
	if len(v) != 8 {
		str := fmt.Sprintf("balance: short read (expected 8 bytes, "+
			"read %v)", len(v))
		return 0, storeError(wtxmgr.ErrData, str, nil)
	}
	return btcutil.Amount(byteOrder.Uint64(v)), nil
}

func putMinedBalance(ns walletdb.ReadWriteBucket, amt btcutil.Amount) error {
	v := make([]byte, 8)
	byteOrder.PutUint64(v, uint64(amt))
	err := ns.Put(rootMinedBalance, v)
	if err != nil {
		str := "failed to put balance"
		return storeError(wtxmgr.ErrDatabase, str, err)
	}
	return nil
}

func readRawTxRecord(txHash *chainhash.Hash, v []byte, rec *wtxmgr.TxRecord) error {
	if len(v) < 8 {
		str := fmt.Sprintf("%s: short read (expected %d bytes, read %d)",
			bucketTxRecords, 8, len(v))
		return storeError(wtxmgr.ErrData, str, nil)
	}
	rec.Hash = *txHash
	rec.Received = time.Unix(int64(byteOrder.Uint64(v)), 0)
	err := rec.MsgTx.Deserialize(bytes.NewReader(v[8:]))
	if err != nil {
		str := fmt.Sprintf("%s: failed to deserialize transaction %v",
			bucketTxRecords, txHash)
		return storeError(wtxmgr.ErrData, str, err)
	}
	return nil
}

func existsRawUnspent(ns walletdb.ReadBucket, k []byte) (credKey []byte) {
	if len(k) < 36 {
		return nil
	}
	v := ns.NestedReadBucket(bucketUnspent).Get(k)
	if len(v) < 36 {
		return nil
	}
	credKey = make([]byte, 72)
	copy(credKey, k[:32])
	copy(credKey[32:68], v)
	copy(credKey[68:72], k[32:36])
	return credKey
}

func putRawUnmined(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketUnmined).Put(k, v)
	if err != nil {
		str := "failed to put unmined record"
		return storeError(wtxmgr.ErrDatabase, str, err)
	}
	return nil
}

func putRawUnminedInput(ns walletdb.ReadWriteBucket, k, v []byte) error {
	spendTxHashes := ns.NestedReadBucket(bucketUnminedInputs).Get(k)
	spendTxHashes = append(spendTxHashes, v...)
	err := ns.NestedReadWriteBucket(bucketUnminedInputs).Put(k, spendTxHashes)
	if err != nil {
		str := "failed to put unmined input"
		return storeError(wtxmgr.ErrDatabase, str, err)
	}

	return nil
}

func fetchUnminedInputSpendTxHashes(ns walletdb.ReadBucket, k []byte) []chainhash.Hash {
	rawSpendTxHashes := ns.NestedReadBucket(bucketUnminedInputs).Get(k)
	if rawSpendTxHashes == nil {
		return nil
	}

	spendTxHashes := make([]chainhash.Hash, 0, len(rawSpendTxHashes)/32)
	for len(rawSpendTxHashes) > 0 {
		var spendTxHash chainhash.Hash
		copy(spendTxHash[:], rawSpendTxHashes[:32])
		spendTxHashes = append(spendTxHashes, spendTxHash)
		rawSpendTxHashes = rawSpendTxHashes[32:]
	}

	return spendTxHashes
}

func existsRawUnmined(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketUnmined).Get(k)
}

func deleteRawUnminedCredit(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketUnminedCredits).Delete(k)
	if err != nil {
		str := "failed to delete unmined credit"
		return storeError(wtxmgr.ErrDatabase, str, err)
	}
	return nil
}

func deleteRawUnminedInput(ns walletdb.ReadWriteBucket, outPointKey []byte,
	targetSpendHash chainhash.Hash) error {

	unminedInputs := ns.NestedReadWriteBucket(bucketUnminedInputs)
	spendHashes := unminedInputs.Get(outPointKey)
	if len(spendHashes) == 0 {
		return nil
	}

	var newSpendHashes []byte
	numHashes := len(spendHashes) / 32
	for i, idx := 0, 0; i < numHashes; i, idx = i+1, idx+32 {
		spendHash := spendHashes[idx : idx+32]
		if !bytes.Equal(targetSpendHash[:], spendHash) {
			newSpendHashes = append(newSpendHashes, spendHash...)
		}
	}

	var err error
	if len(newSpendHashes) == 0 {
		err = unminedInputs.Delete(outPointKey)
	} else {
		err = unminedInputs.Put(outPointKey, newSpendHashes)
	}
	if err != nil {
		str := "failed to delete unmined input spend"
		return storeError(wtxmgr.ErrDatabase, str, err)
	}

	return nil
}

func deleteRawUnmined(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketUnmined).Delete(k)
	if err != nil {
		str := "failed to delete unmined record"
		return storeError(wtxmgr.ErrDatabase, str, err)
	}
	return nil
}

func readRawUnminedHash(k []byte, txHash *chainhash.Hash) error {
	if len(k) < 32 {
		str := "short unmined key"
		return storeError(wtxmgr.ErrData, str, nil)
	}
	copy(txHash[:], k)
	return nil
}

type blockIterator struct {

	c    walletdb.ReadWriteCursor

	seek []byte

	ck   []byte

	cv   []byte

	elem BlockRecord

	err  error

}
	
	func makeReverseBlockIterator(ns walletdb.ReadWriteBucket) blockIterator {
		seek := make([]byte, 4)
		byteOrder.PutUint32(seek, ^uint32(0))
		c := ns.NestedReadWriteBucket(bucketBlocks).ReadWriteCursor()
		return blockIterator{c: c, seek: seek}
	}
	
	func keyTxRecord(txHash *chainhash.Hash, block *wtxmgr.Block) []byte {
		k := make([]byte, 68)
		copy(k, txHash[:])
		byteOrder.PutUint32(k[32:36], uint32(block.Height))
		copy(k[36:68], block.Hash[:])
		return k
	}
	
	func existsRawTxRecord(ns walletdb.ReadBucket, k []byte) (v []byte) {
		return ns.NestedReadBucket(bucketTxRecords).Get(k)
	}
	
	func deleteTxRecord(ns walletdb.ReadWriteBucket, txHash *chainhash.Hash, block *wtxmgr.Block) error {
		k := keyTxRecord(txHash, block)
		return ns.NestedReadWriteBucket(bucketTxRecords).Delete(k)
	}
	
	func existsCredit(ns walletdb.ReadBucket, txHash *chainhash.Hash, index uint32, block *wtxmgr.Block) (k, v []byte) {
		k = keyCredit(txHash, index, block)
		v = ns.NestedReadBucket(bucketCredits).Get(k)
		return
	}
	
	func existsUnspent(ns walletdb.ReadBucket, outPoint *wire.OutPoint) (k, credKey []byte) {
		k = wtxmgr.CanonicalOutPoint(&outPoint.Hash, outPoint.Index)
		credKey = existsRawUnspent(ns, k)
		return k, credKey
	}
	
	func deleteRawUnspent(ns walletdb.ReadWriteBucket, k []byte) error {
		err := ns.NestedReadWriteBucket(bucketUnspent).Delete(k)
		if err != nil {
			str := "failed to delete unspent"
			return storeError(wtxmgr.ErrDatabase, str, err)
		}
		return nil
	}
	
	func deleteRawCredit(ns walletdb.ReadWriteBucket, k []byte) error {
		err := ns.NestedReadWriteBucket(bucketCredits).Delete(k)
		if err != nil {
			str := "failed to delete credit"
			return storeError(wtxmgr.ErrDatabase, str, err)
		}
		return nil
	}
	
	func (it *blockIterator) prev() bool {
		if it.c == nil {
			return false
		}
	
		if it.ck == nil {
			it.ck, it.cv = it.c.Seek(it.seek)
			if !bytes.HasPrefix(it.ck, it.seek) {
				it.ck, it.cv = it.c.Prev()
			}
		} else {
			it.ck, it.cv = it.c.Prev()
		}
		if it.ck == nil {
			it.c = nil
			return false
		}
	
		err := readRawBlockRecord(it.ck, it.cv, &it.elem)
		if err != nil {
			it.c = nil
			it.err = err
			return false
		}
	
		return true
	}
	
	func (it *blockIterator) reposition(height int32) {
		it.c.Seek(keyBlockRecord(height))
	}
	
	func keyBlockRecord(height int32) []byte {
		k := make([]byte, 4)
		byteOrder.PutUint32(k, uint32(height))
		return k
	}
	
	func readRawBlockRecord(k, v []byte, block *BlockRecord) error {
	if len(k) < 4 {
		str := fmt.Sprintf("%s: short key (expected %d bytes, read %d)",
			bucketBlocks, 4, len(k))
		return storeError(wtxmgr.ErrData, str, nil)
	}
	if len(v) < 44 {
		str := fmt.Sprintf("%s: short read (expected %d bytes, read %d)",
			bucketBlocks, 44, len(v))
		return storeError(wtxmgr.ErrData, str, nil)
	}
	numTransactions := int(byteOrder.Uint32(v[40:44]))
	expectedLen := 44 + chainhash.HashSize*numTransactions
	if len(v) < expectedLen {
		str := fmt.Sprintf("%s: short read (expected %d bytes, read %d)",
			bucketBlocks, expectedLen, len(v))
		return storeError(wtxmgr.ErrData, str, nil)
	}

	block.Height = int32(byteOrder.Uint32(k))
	copy(block.Hash[:], v)
	block.Time = time.Unix(int64(byteOrder.Uint64(v[32:40])), 0)
	block.Transactions = make([]chainhash.Hash, numTransactions)
	off := 44
	for i := range block.Transactions {
		copy(block.Transactions[i][:], v[off:])
		off += chainhash.HashSize
	}

	return nil
}

func deleteBlockRecord(ns walletdb.ReadWriteBucket, height int32) error {
	k := keyBlockRecord(height)
	return ns.NestedReadWriteBucket(bucketBlocks).Delete(k)
}

func keyCredit(txHash *chainhash.Hash, index uint32, block *wtxmgr.Block) []byte {
	k := make([]byte, 72)
	copy(k, txHash[:])
	byteOrder.PutUint32(k[32:36], uint32(block.Height))
	copy(k[36:68], block.Hash[:])
	byteOrder.PutUint32(k[68:72], index)
	return k
}

func unspendRawCredit(ns walletdb.ReadWriteBucket, k []byte) (btcutil.Amount, error) {
	b := ns.NestedReadWriteBucket(bucketCredits)
	v := b.Get(k)
	if v == nil {
		return 0, nil
	}
	newv := make([]byte, 9)
	copy(newv, v)
	newv[8] &^= 1 << 0

	err := b.Put(k, newv)
	if err != nil {
		str := "failed to put credit"
		return 0, storeError(wtxmgr.ErrDatabase, str, err)
	}
	return btcutil.Amount(byteOrder.Uint64(v[0:8])), nil
}

func fetchRawCreditUnspentValue(k []byte) ([]byte, error) {
	if len(k) < 72 {
		str := fmt.Sprintf("%s: short key (expected %d bytes, read %d)",
			bucketCredits, 72, len(k))
		return nil, storeError(wtxmgr.ErrData, str, nil)
	}
	return k[32:68], nil
}

func fetchRawCreditAmountChange(v []byte) (btcutil.Amount, bool, error) {
	if len(v) < 9 {
		str := fmt.Sprintf("%s: short read (expected %d bytes, read %d)",
			bucketCredits, 9, len(v))
		return 0, false, storeError(wtxmgr.ErrData, str, nil)
	}
	return btcutil.Amount(byteOrder.Uint64(v)), v[8]&(1<<1) != 0, nil
}

func existsDebit(ns walletdb.ReadBucket, txHash *chainhash.Hash, index uint32, block *wtxmgr.Block) (k, credKey []byte, err error) {
	k = keyDebit(txHash, index, block)
	v := ns.NestedReadBucket(bucketDebits).Get(k)
	if v == nil {
		return nil, nil, nil
	}
	if len(v) < 80 {
		str := fmt.Sprintf("%s: short read (expected 80 bytes, read %v)",
			bucketDebits, len(v))
		return nil, nil, storeError(wtxmgr.ErrData, str, nil)
	}
	return k, v[8:80], nil
}

func keyDebit(txHash *chainhash.Hash, index uint32, block *wtxmgr.Block) []byte {
	k := make([]byte, 72)
	copy(k, txHash[:])
	byteOrder.PutUint32(k[32:36], uint32(block.Height))
	copy(k[36:68], block.Hash[:])
	byteOrder.PutUint32(k[68:72], index)
	return k
}

func deleteRawDebit(ns walletdb.ReadWriteBucket, k []byte) error {

	err := ns.NestedReadWriteBucket(bucketDebits).Delete(k)

	if err != nil {

		str := "failed to delete debit"

		return storeError(wtxmgr.ErrDatabase, str, err)

	}

	return nil

}



func putRawUnspent(ns walletdb.ReadWriteBucket, k, v []byte) error {

	err := ns.NestedReadWriteBucket(bucketUnspent).Put(k, v)

	if err != nil {

		str := "cannot put unspent"

		return storeError(wtxmgr.ErrDatabase, str, err)

	}

	return nil

}



func putRawUnminedCredit(ns walletdb.ReadWriteBucket, k, v []byte) error {

	err := ns.NestedReadWriteBucket(bucketUnminedCredits).Put(k, v)

	if err != nil {

		str := "cannot put unmined credit"

		return storeError(wtxmgr.ErrDatabase, str, err)

	}

	return nil

}

func readCanonicalOutPoint(k []byte, op *wire.OutPoint) error {
	if len(k) < 36 {
		str := "short canonical outpoint"
		return storeError(wtxmgr.ErrData, str, nil)
	}
	copy(op.Hash[:], k)
	op.Index = byteOrder.Uint32(k[32:36])
	return nil
}

func readUnspentBlock(v []byte, block *wtxmgr.Block) error {
	if len(v) < 36 {
		str := "short unspent value"
		return storeError(wtxmgr.ErrData, str, nil)
	}
	block.Height = int32(byteOrder.Uint32(v))
	return nil
}

func fetchRawUnminedCreditAmount(v []byte) (btcutil.Amount, error) {
	if len(v) < 9 {
		str := "short unmined credit value"
		return 0, storeError(wtxmgr.ErrData, str, nil)
	}
	return btcutil.Amount(byteOrder.Uint64(v)), nil
}

func isLockedOutput(ns walletdb.ReadBucket, op wire.OutPoint,
	timeNow time.Time) (wtxmgr.LockID, time.Time, bool) {

	lockedOutputs := ns.NestedReadBucket(bucketLockedOutputs)
	if lockedOutputs == nil {
		return wtxmgr.LockID{}, time.Time{}, false
	}

	k := wtxmgr.CanonicalOutPoint(&op.Hash, op.Index)
	v := lockedOutputs.Get(k)
	if v == nil {
		return wtxmgr.LockID{}, time.Time{}, false
	}
	lockID, expiry := deserializeLockedOutput(v)

	if !timeNow.Before(expiry) {
		return wtxmgr.LockID{}, time.Time{}, false
	}

	return lockID, expiry, true
}

func fetchRawCreditAmount(v []byte) (btcutil.Amount, error) {
	if len(v) < 9 {
		str := fmt.Sprintf("%s: short read (expected %d bytes, read %d)",
			bucketCredits, 9, len(v))
		return 0, storeError(wtxmgr.ErrData, str, nil)
	}
	return btcutil.Amount(byteOrder.Uint64(v)), nil
}

func existsRawUnminedInput(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketUnminedInputs).Get(k)
}

func fetchTxRecord(ns walletdb.ReadBucket, txHash *chainhash.Hash, block *wtxmgr.Block) (*wtxmgr.TxRecord, error) {
	k := keyTxRecord(txHash, block)
	v := ns.NestedReadBucket(bucketTxRecords).Get(k)

	rec := new(wtxmgr.TxRecord)
	err := readRawTxRecord(txHash, v, rec)
	return rec, err
}

func makeReadReverseBlockIterator(ns walletdb.ReadBucket) blockIterator {
	seek := make([]byte, 4)
	byteOrder.PutUint32(seek, ^uint32(0))
	c := ns.NestedReadBucket(bucketBlocks).ReadCursor()
	return blockIterator{c: readCursor{c}, seek: seek}
}

func fetchRawCreditAmountSpent(v []byte) (btcutil.Amount, bool, error) {
	if len(v) < 9 {
		str := fmt.Sprintf("%s: short read (expected %d bytes, read %d)",
			bucketCredits, 9, len(v))
		return 0, false, storeError(wtxmgr.ErrData, str, nil)
	}
	return btcutil.Amount(byteOrder.Uint64(v)), v[8]&(1<<0) != 0, nil
}

func deserializeLockedOutput(v []byte) (wtxmgr.LockID, time.Time) {
	var id wtxmgr.LockID
	copy(id[:], v[:len(id)])
	expiry := time.Unix(int64(byteOrder.Uint64(v[len(id):])), 0)
	return id, expiry
}

type readCursor struct {
	walletdb.ReadCursor
}

func (r readCursor) Delete() error {
	str := "failed to delete current cursor item from read-only cursor"
	return storeError(wtxmgr.ErrDatabase, str, walletdb.ErrTxNotWritable)
}
