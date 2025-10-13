// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightningnetwork/lnd/clock"
)

const (
	// TxLabelLimit is the length limit we impose on transaction labels.
	TxLabelLimit = 500
)

var (
	// ErrEmptyLabel is returned when an attempt to write a label that is
	// empty is made.
	ErrEmptyLabel = errors.New("empty transaction label not allowed")

	// ErrLabelTooLong is returned when an attempt to write a label that is
	// to long is made.
	ErrLabelTooLong = errors.New("transaction label exceeds limit")

	// ErrNoLabelBucket is returned when the bucket holding optional
	// transaction labels is not found. This occurs when no transactions
	// have been labelled yet.
	ErrNoLabelBucket = errors.New("labels bucket does not exist")

	// ErrTxLabelNotFound is returned when no label is found for a
	// transaction hash.
	ErrTxLabelNotFound = errors.New("label for transaction not found")

	// ErrUnknownOutput is an error returned when an output not known to the
	// wallet is attempted to be locked.
	ErrUnknownOutput = errors.New("unknown output")

	// ErrOutputAlreadyLocked is an error returned when an output has
	// already been locked to a different ID.
	ErrOutputAlreadyLocked = errors.New("output already locked")

	// ErrOutputUnlockNotAllowed is an error returned when an output unlock
	// is attempted with a different ID than the one which locked it.
	ErrOutputUnlockNotAllowed = errors.New("output unlock not alowed")

	// ErrDuplicateTx is returned when attempting to record a mined or
	// unmined transaction that is already recorded.
	ErrDuplicateTx = errors.New("transaction already exists")
)

// Block contains the minimum amount of data to uniquely identify any block on
// either the best or side chain.
type Block struct {
	Hash   chainhash.Hash
	Height int32
}

// BlockMeta contains the unique identification for a block and any metadata
// pertaining to the block.  At the moment, this additional metadata only
// includes the block time from the block header.
type BlockMeta struct {
	Block
	Time time.Time
}

// blockRecord is an in-memory representation of the block record saved in the
// database.
type blockRecord struct {
	Block
	Time         time.Time
	transactions []chainhash.Hash
}

// incidence records the block hash and blockchain height of a mined transaction.
// Since a transaction hash alone is not enough to uniquely identify a mined
// transaction (duplicate transaction hashes are allowed), the incidence is used
// instead.
type incidence struct {
	txHash chainhash.Hash
	block  Block
}

// indexedIncidence records the transaction incidence and an input or output
// index.
type indexedIncidence struct {
	incidence
	index uint32
}

// debit records the debits a transaction record makes from previous wallet
// transaction credits.
type debit struct {
	txHash chainhash.Hash
	index  uint32
	amount btcutil.Amount
	spends indexedIncidence
}

// credit describes a transaction output which was or is spendable by wallet.
type credit struct {
	outPoint wire.OutPoint
	block    Block
	amount   btcutil.Amount
	change   bool
	spentBy  indexedIncidence // Index == ^uint32(0) if unspent
}

// TxRecord represents a transaction managed by the Store.
type TxRecord struct {
	MsgTx        wire.MsgTx
	Hash         chainhash.Hash
	Received     time.Time
	SerializedTx []byte // Optional: may be nil
}

// LockedOutput is a type that contains an outpoint of an UTXO and its lock
// lease information.
type LockedOutput struct {
	Outpoint   wire.OutPoint
	LockID     LockID
	Expiration time.Time
}

// NewTxRecord creates a new transaction record that may be inserted into the
// store.  It uses memoization to save the transaction hash and the serialized
// transaction.
func NewTxRecord(serializedTx []byte, received time.Time) (*TxRecord, error) {
	rec := &TxRecord{
		Received:     received,
		SerializedTx: serializedTx,
	}
	err := rec.MsgTx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		str := "failed to deserialize transaction"
		return nil, storeError(ErrInput, str, err)
	}
	copy(rec.Hash[:], chainhash.DoubleHashB(serializedTx))
	return rec, nil
}

// NewTxRecordFromMsgTx creates a new transaction record that may be inserted
// into the store.
func NewTxRecordFromMsgTx(msgTx *wire.MsgTx, received time.Time) (*TxRecord, error) {
	buf := bytes.NewBuffer(make([]byte, 0, msgTx.SerializeSize()))
	err := msgTx.Serialize(buf)
	if err != nil {
		str := "failed to serialize transaction"
		return nil, storeError(ErrInput, str, err)
	}
	rec := &TxRecord{
		MsgTx:        *msgTx,
		Received:     received,
		SerializedTx: buf.Bytes(),
		Hash:         msgTx.TxHash(),
	}

	return rec, nil
}

// Credit is the type representing a transaction output which was spent or
// is still spendable by wallet.  A UTXO is an unspent Credit, but not all
// Credits are UTXOs.
type Credit struct {
	wire.OutPoint
	BlockMeta
	Amount       btcutil.Amount
	PkScript     []byte
	Received     time.Time
	FromCoinBase bool
}

// LockID represents a unique context-specific ID assigned to an output lock.
type LockID [32]byte

// Store implements a transaction store for storing and managing wallet
// transactions.
type Store struct {
	ChainParams *chaincfg.Params

	// clock is used to determine when outputs locks have expired.
	clock clock.Clock

	// Event callbacks.  These execute in the same goroutine as the wtxmgr
	// caller.
	NotifyUnspent func(hash *chainhash.Hash, index uint32)
}

// A compile-time assertion to ensure that Store implements the TxStore
// interface.
var _ TxStore = (*Store)(nil)

// Open opens the wallet transaction store from a walletdb namespace.  If the
// store does not exist, ErrNoExist is returned. `lockDuration` represents how
// long outputs are locked for.
func Open(ns walletdb.ReadBucket, chainParams *chaincfg.Params) (*Store, error) {

	// Open the store.
	err := openStore(ns)
	if err != nil {
		return nil, err
	}
	s := &Store{ChainParams: chainParams, clock: clock.NewDefaultClock(), NotifyUnspent: nil}
	return s, nil
}

// Create creates a new persistent transaction store in the walletdb namespace.
// Creating the store when one already exists in this namespace will error with
// ErrAlreadyExists.
func Create(ns walletdb.ReadWriteBucket) error {
	return createStore(ns)
}

// updateMinedBalance updates the mined balance within the store, if changed,
// after processing the given transaction record.
func (s *Store) updateMinedBalance(ns walletdb.ReadWriteBucket, rec *TxRecord,
	block *BlockMeta) error {

	// Fetch the mined balance in case we need to update it.
	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}

	// Add a debit record for each unspent credit spent by this transaction.
	// The index is set in each iteration below.
	spender := indexedIncidence{
		incidence: incidence{
			txHash: rec.Hash,
			block:  block.Block,
		},
	}

	newMinedBalance := minedBalance
	for i, input := range rec.MsgTx.TxIn {
		unspentKey, credKey := existsUnspent(ns, &input.PreviousOutPoint)
		if credKey == nil {
			// Debits for unmined transactions are not explicitly
			// tracked.  Instead, all previous outputs spent by any
			// unmined transaction are added to a map for quick
			// lookups when it must be checked whether a mined
			// output is unspent or not.
			//
			// Tracking individual debits for unmined transactions
			// could be added later to simplify (and increase
			// performance of) determining some details that need
			// the previous outputs (e.g. determining a fee), but at
			// the moment that is not done (and a db lookup is used
			// for those cases instead).  There is also a good
			// chance that all unmined transaction handling will
			// move entirely to the db rather than being handled in
			// memory for atomicity reasons, so the simplist
			// implementation is currently used.
			continue
		}

		// If this output is relevant to us, we'll mark the it as spent
		// and remove its amount from the store.
		spender.index = uint32(i)
		amt, err := spendCredit(ns, credKey, &spender)
		if err != nil {
			return err
		}
		err = putDebit(
			ns, &rec.Hash, uint32(i), amt, &block.Block, credKey,
		)
		if err != nil {
			return err
		}
		if err := deleteRawUnspent(ns, unspentKey); err != nil {
			return err
		}

		newMinedBalance -= amt
	}

	// For each output of the record that is marked as a credit, if the
	// output is marked as a credit by the unconfirmed store, remove the
	// marker and mark the output as a credit in the db.
	//
	// Moved credits are added as unspents, even if there is another
	// unconfirmed transaction which spends them.
	cred := credit{
		outPoint: wire.OutPoint{Hash: rec.Hash},
		block:    block.Block,
		spentBy:  indexedIncidence{index: ^uint32(0)},
	}

	it := makeUnminedCreditIterator(ns, &rec.Hash)
	for it.next() {
		// TODO: This should use the raw apis.  The credit value (it.cv)
		// can be moved from unmined directly to the credits bucket.
		// The key needs a modification to include the block
		// height/hash.
		index, err := fetchRawUnminedCreditIndex(it.ck)
		if err != nil {
			return err
		}
		amount, change, err := fetchRawUnminedCreditAmountChange(it.cv)
		if err != nil {
			return err
		}

		cred.outPoint.Index = index
		cred.amount = amount
		cred.change = change

		if err := putUnspentCredit(ns, &cred); err != nil {
			return err
		}
		err = putUnspent(ns, &cred.outPoint, &block.Block)
		if err != nil {
			return err
		}

		newMinedBalance += amount
	}
	if it.err != nil {
		return it.err
	}

	// Update the balance if it has changed.
	if newMinedBalance != minedBalance {
		return putMinedBalance(ns, newMinedBalance)
	}

	return nil
}

// deleteUnminedTx deletes an unmined transaction from the store.
//
// NOTE: This should only be used once the transaction has been mined.
func (s *Store) deleteUnminedTx(ns walletdb.ReadWriteBucket, rec *TxRecord) error {
	for _, input := range rec.MsgTx.TxIn {
		prevOut := input.PreviousOutPoint
		k := CanonicalOutPoint(&prevOut.Hash, prevOut.Index)
		if err := deleteRawUnminedInput(ns, k, rec.Hash); err != nil {
			return err
		}
	}
	for i := range rec.MsgTx.TxOut {
		k := CanonicalOutPoint(&rec.Hash, uint32(i))
		if err := deleteRawUnminedCredit(ns, k); err != nil {
			return err
		}
	}

	return deleteRawUnmined(ns, rec.Hash[:])
}

// InsertTx records a transaction as belonging to a wallet's transaction
// history.  If block is nil, the transaction is considered unspent, and the
// transaction's index must be unset.
func (s *Store) InsertTx(ns walletdb.ReadWriteBucket, rec *TxRecord,
	block *BlockMeta) error {
	_, err := s.InsertTxCheckIfExists(ns, rec, block)
	return err
}

// InsertTxCheckIfExists records a transaction as belonging to a wallet's
// transaction history.  If block is nil, the transaction is considered unspent,
// and the transaction's index must be unset. It will return true if the
// transaction was already recorded prior to the call.
func (s *Store) InsertTxCheckIfExists(ns walletdb.ReadWriteBucket,
	rec *TxRecord, block *BlockMeta) (bool, error) {

	var err error
	if block == nil {
		if err = s.insertMemPoolTx(ns, rec); err == ErrDuplicateTx {
			return true, nil
		}
		return false, err
	}
	if err = s.insertMinedTx(ns, rec, block); err == ErrDuplicateTx {
		return true, nil
	}
	return false, err
}

// insertMinedTx inserts a new transaction record for a mined transaction.
func (s *Store) insertMinedTx(ns walletdb.ReadWriteBucket, rec *TxRecord,
	block *BlockMeta) error {

	// If a transaction record for this hash and block already exists, we can
	// return early.
	if k, _ := existsTxRecord(ns, &rec.Hash, &block.Block); k != nil {
		return ErrDuplicateTx
	}

	// If the transaction is unconfirmed, we'll remove it from the unconfirmed
	// store and instead create a new mined transaction record.
	if v := existsRawUnmined(ns, rec.Hash[:]); v != nil {
		log.Infof("Moving unconfirmed transaction %v to mined",
			rec.Hash)

		if err := s.deleteUnminedTx(ns, rec); err != nil {
			return err
		}
	}

	// We'll then go through all of its inputs and check if they spend any of
	// our previous credits.
	if err := s.removeDoubleSpends(ns, rec); err != nil {
		return err
	}

	// We'll also update the block record for this block to include this
	// transaction.
	if err := s.addTxToBlock(ns, block, &rec.Hash); err != nil {
		return err
	}

	// Then, we'll update the mined balance for this transaction.
	if err := s.updateMinedBalance(ns, rec, block); err != nil {
		return err
	}

	// Finally, we'll insert the mined transaction record.
	return putTxRecord(ns, rec, &block.Block)
}

// AddCredit marks a transaction record as containing a transaction output
// spendable by wallet.  The output is added unspent, and is marked spent
// when a new transaction spending the output is inserted into the store.
//
// TODO(jrick): This should not be necessary.  Instead, pass the indexes
// that are known to contain credits when a transaction or merkleblock is
// inserted into the store.
func (s *Store) AddCredit(ns walletdb.ReadWriteBucket, rec *TxRecord, block *BlockMeta, index uint32, change bool) error {
	if int(index) >= len(rec.MsgTx.TxOut) {
		str := "transaction output does not exist"
		return storeError(ErrInput, str, nil)
	}

	isNew, err := s.addCredit(ns, rec, block, index, change)
	if err == nil && isNew && s.NotifyUnspent != nil {
		s.NotifyUnspent(&rec.Hash, index)
	}
	return err
}

// addCredit is an AddCredit helper that runs in an update transaction.  The
// bool return specifies whether the unspent output is newly added (true) or a
// duplicate (false).
func (s *Store) addCredit(ns walletdb.ReadWriteBucket, rec *TxRecord, block *BlockMeta, index uint32, change bool) (bool, error) {
	txOutAmt := btcutil.Amount(rec.MsgTx.TxOut[index].Value)

	if block == nil {
		// If the outpoint that we should mark as credit already exists
		// within the store, either as unconfirmed or confirmed, then we
		// have nothing left to do and can exit.
		k := CanonicalOutPoint(&rec.Hash, index)
		if existsRawUnminedCredit(ns, k) != nil {
			log.Tracef("Ignoring credit for outpoint %v:%v",
				rec.Hash.String(), index)

			return false, nil
		}
		if _, tv := latestTxRecord(ns, &rec.Hash); tv != nil {
			log.Tracef("Ignoring credit for existing confirmed transaction %v",
				rec.Hash.String())
			return false, nil
		}
		v := ValueUnminedCredit(txOutAmt, change)

		log.Debugf("Add unmined credit=%v for outpoint %v:%v", txOutAmt,
			rec.Hash, index)

		return true, putRawUnminedCredit(ns, k, v)
	}

	k, v := existsCredit(ns, &rec.Hash, index, &block.Block)
	if v != nil {
		log.Tracef("Ignoring exsiting credit for outpoint %v:%v",
			rec.Hash.String(), index)

		return false, nil
	}

	log.Debugf("Add mined credit=%v for outpoint %v:%v", txOutAmt, rec.Hash,
		index)

	cred := credit{
		outPoint: wire.OutPoint{
			Hash:  rec.Hash,
			Index: index,
		},
		block:   block.Block,
		amount:  txOutAmt,
		change:  change,
		spentBy: indexedIncidence{index: ^uint32(0)},
	}
	v = valueUnspentCredit(&cred)
	err := putRawCredit(ns, k, v)
	if err != nil {
		return false, err
	}

	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return false, err
	}
	err = putMinedBalance(ns, minedBalance+txOutAmt)
	if err != nil {
		return false, err
	}

	return true, putUnspent(ns, &cred.outPoint, &block.Block)
}

// addTxToBlock adds a transaction hash to a block record.
func (s *Store) addTxToBlock(ns walletdb.ReadWriteBucket, block *BlockMeta,
	txHash *chainhash.Hash) error {

	k, v := existsBlockRecord(ns, block.Height)
	if v == nil {
		return putBlockRecord(ns, block, txHash)
	}
	newVal, err := appendRawBlockRecord(v, txHash)
	if err != nil {
		return err
	}
	return putRawBlockRecord(ns, k, newVal)
}

// TODO(yy): The fetchCredits method suffers from several architectural and
// performance issues that should be addressed in a future refactoring:
//
//  1. **N+1 Query Problem:** The function iterates through all unspent outputs
//     and performs a separate database lookup (`fetchTxRecord`) for each one to
//     retrieve its full details. For a wallet with a large number of UTXOs,
//     this results in an excessive number of database reads, leading to poor
//     performance.
//
//  2. **Inefficient Data Storage:** The root cause of the N+1 problem is that
//     the `unspent` bucket only stores a reference to the transaction, not the
//     critical data (Amount, PkScript) itself. The schema should be
//     denormalized to include this data directly in the `unspent` value, which
//     would turn the N+1 query into a single, efficient bucket scan.
//
//  3. **Code Duplication:** The logic for iterating over mined and unmined
//     credits is nearly identical, leading to significant code duplication. This
//     should be consolidated into a more generic helper function.
//
//  4. **Leaky Abstraction:** The use of multiple boolean flags
//     (`includeLocked`, `populateFullDetails`) to control behavior is a sign of
//     a leaky abstraction. A better API would provide more specific query
//     functions rather than a single, complex function with many toggles.
//
//  5. **Lack of Pagination:** The function loads all results into a single
//     in-memory slice, which can be memory-intensive for wallets with a large
//     UTXO set. A more scalable approach would use an iterator pattern.
//
// fetchCredits retrieves credits from the store based on the provided filters.
// It iterates over both mined (unspent) and unmined credits.
//
// Parameters:
//   - ns: The database bucket to read from.
//   - includeLocked: If true, credits locked by LockOutput are included.
//   - includeSpentByUnmined: If true, credits spent by unmined transactions
//     are included.
//   - populateFullDetails: If true, all fields of the Credit struct are
//     populated. Otherwise, only OutPoint and PkScript are populated.
func fetchCredits(ns walletdb.ReadBucket, includeLocked bool,
	includeSpentByUnmined bool,
	populateFullDetails bool) ([]Credit, error) {

	var credits []Credit
	now := time.Now() // Cache current time for lock checks

	// Iterate over mined unspent credits (bucketUnspent).
	unspentBucket := ns.NestedReadBucket(bucketUnspent)
	if unspentBucket != nil {
		err := unspentBucket.ForEach(func(k, v []byte) error {
			var op wire.OutPoint
			err := readCanonicalOutPoint(k, &op)
			if err != nil {
				return err
			}

			// Check if locked, skip if necessary.
			if !includeLocked {
				_, _, isLocked := isLockedOutput(ns, op, now)
				if isLocked {
					return nil
				}
			}

			// Check if spent by unmined, skip if necessary.
			if !includeSpentByUnmined {
				if existsRawUnminedInput(ns, k) != nil {
					return nil
				}
			}

			// Fetch the transaction record to get PkScript and
			// potentially other details.
			var block Block
			err = readUnspentBlock(v, &block)
			if err != nil {
				return err
			}

			// TODO(jrick): reading the entire transaction should
			// be avoidable. Creating the credit only requires the
			// output amount and pkScript.
			rec, err := fetchTxRecord(ns, &op.Hash, &block)
			if err != nil {
				// Wrap the error for context.
				return fmt.Errorf("unable to retrieve tx %v "+
					"for mined credit: %w", op.Hash, err)
			}

			txOut := rec.MsgTx.TxOut[op.Index]
			cred := Credit{
				OutPoint: op,
				PkScript: txOut.PkScript,
			}

			// Populate full details if requested.
			if populateFullDetails {
				blockTime, err := fetchBlockTime(
					ns, block.Height,
				)
				if err != nil {
					// Wrap the error for context.
					return fmt.Errorf("unable to fetch "+
						"block time for height %d: %w",
						block.Height, err)
				}

				cred.BlockMeta = BlockMeta{
					Block: block,
					Time:  blockTime,
				}
				cred.Amount = btcutil.Amount(txOut.Value)
				cred.Received = rec.Received
				cred.FromCoinBase = blockchain.IsCoinBaseTx(
					&rec.MsgTx,
				)
			}

			credits = append(credits, cred)
			return nil
		})
		if err != nil {
			// Check if it's already a storeError, otherwise wrap
			// it.
			if _, ok := err.(Error); ok {
				return nil, err
			}

			str := "failed iterating unspent bucket"
			return nil, storeError(ErrDatabase, str, err)
		}
	}

	// Iterate over unmined credits (bucketUnminedCredits).
	unminedCreditsBucket := ns.NestedReadBucket(bucketUnminedCredits)
	if unminedCreditsBucket != nil {
		err := unminedCreditsBucket.ForEach(func(k, v []byte) error {
			var op wire.OutPoint
			if err := readCanonicalOutPoint(k, &op); err != nil {
				return err
			}

			// Check if locked, skip if necessary.
			if !includeLocked {
				_, _, isLocked := isLockedOutput(ns, op, now)
				if isLocked {
					return nil
				}
			}

			// Check if spent by unmined, skip if necessary.
			if !includeSpentByUnmined {
				if existsRawUnminedInput(ns, k) != nil {
					return nil
				}
			}

			// Fetch the transaction record to get PkScript and
			// potentially other details.
			recVal := existsRawUnmined(ns, op.Hash[:])

			// existsRawUnmined should always return a value for a
			// key in bucketUnminedCredits, but check defensively.
			if recVal == nil {
				log.Warnf("Unmined credit %v points to "+
					"non-existent unmined tx record %v", op,
					op.Hash)

				// Skip this credit as its tx record is missing.
				return nil
			}

			var rec TxRecord
			err := readRawTxRecord(&op.Hash, recVal, &rec)
			if err != nil {
				// Wrap the error for context.
				return fmt.Errorf("unable to retrieve raw tx "+
					"%v for unmined credit: %w", op.Hash,
					err)
			}

			txOut := rec.MsgTx.TxOut[op.Index]
			cred := Credit{
				OutPoint: op,
				PkScript: txOut.PkScript,
			}

			// Populate full details if requested.
			if populateFullDetails {
				cred.BlockMeta = BlockMeta{
					// Unmined height.
					Block: Block{Height: -1},
				}
				cred.Amount = btcutil.Amount(txOut.Value)
				cred.Received = rec.Received
				cred.FromCoinBase = blockchain.IsCoinBaseTx(
					&rec.MsgTx,
				)
			}

			credits = append(credits, cred)
			return nil
		})
		if err != nil {
			// Check if it's already a storeError, otherwise wrap
			// it.
			if _, ok := err.(Error); ok {
				return nil, err
			}
			str := "failed iterating unmined credits bucket"
			return nil, storeError(ErrDatabase, str, err)
		}
	}

	return credits, nil
}

// OutputsToWatch returns a list of outputs to monitor during the wallet's
// startup. The returned items are similar to UnspentOutputs, exccept the
// locked outputs and unmined credits are also returned here. In addition, we
// only set the field `OutPoint` and `PkScript` for the `Credit`, as these are
// the only fields used during the rescan.
func (s *Store) OutputsToWatch(ns walletdb.ReadBucket) ([]Credit, error) {
	// OutputsToWatch needs all known outputs (mined and unmined),
	// including locked ones and those spent by other unmined txs,
	// but only requires minimal details (OutPoint, PkScript).
	return fetchCredits(ns, true, true, false)
}

// UnspentOutputs returns all unspent received transaction outputs.
// The order is undefined.
func UnspentOutputs(ns walletdb.ReadBucket) ([]Credit, error) {
	// UnspentOutputs needs outputs that are actually spendable:
	// - Not locked.
	// - Not spent by an unmined transaction.
	// It requires full credit details.
	return fetchCredits(ns, false, false, true)
}

// PutTxLabel validates transaction labels and writes them to disk if they
// are non-zero and within the label length limit. The entry is keyed by the
// transaction hash:
// [0:32] Transaction hash (32 bytes)
//
// The label itself is written to disk in length value format:
// [0:2] Label length
// [2: +len] Label
func (s *Store) PutTxLabel(ns walletdb.ReadWriteBucket, txid chainhash.Hash,
	label string) error {

	if len(label) == 0 {
		return ErrEmptyLabel
	}

	if len(label) > TxLabelLimit {
		return ErrLabelTooLong
	}

	labelBucket, err := ns.CreateBucketIfNotExists(bucketTxLabels)
	if err != nil {
		return err
	}

	labelLen := uint16(len(label))
	var buf bytes.Buffer
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], labelLen)
	if _, err := buf.Write(b[:]); err != nil {
		return err
	}
	if _, err := buf.WriteString(label); err != nil {
		return err
	}

	return labelBucket.Put(txid[:], buf.Bytes())
}

// PutTxLabel writes a label for a tx to the bucket provided. Note that it does
// not perform any validation on the label provided, or check whether there is
// an existing label for the txid.
func PutTxLabel(labelBucket walletdb.ReadWriteBucket, txid chainhash.Hash,
	label string) error {

	// We expect the label length to be limited on creation, so we can
	// store the label's length as a uint16.
	labelLen := uint16(len(label))

	var buf bytes.Buffer

	var b [2]byte
	binary.BigEndian.PutUint16(b[:], labelLen)
	if _, err := buf.Write(b[:]); err != nil {
		return err
	}

	if _, err := buf.WriteString(label); err != nil {
		return err
	}

	return labelBucket.Put(txid[:], buf.Bytes())
}

// FetchTxLabel reads a transaction label from the tx labels bucket. If a label
// with 0 length was written, we return an error, since this is unexpected.
func (s *Store) FetchTxLabel(ns walletdb.ReadBucket, txid chainhash.Hash) (string, error) {
	labelBucket := ns.NestedReadBucket(bucketTxLabels)
	if labelBucket == nil {
		return "", ErrNoLabelBucket
	}

	v := labelBucket.Get(txid[:])
	if v == nil {
		return "", ErrTxLabelNotFound
	}

	return DeserializeLabel(v)
}

// DeserializeLabel reads a deserializes a length-value encoded label from the
// byte array provided.
func DeserializeLabel(v []byte) (string, error) {
	// If the label is empty, return an error.
	length := binary.BigEndian.Uint16(v[0:2])
	if length == 0 {
		return "", ErrEmptyLabel
	}

	// Read the remainder of the bytes into a label string.
	label := string(v[2:])
	return label, nil
}

// isKnownOutput returns whether the output is known to the transaction store
// either as confirmed or unconfirmed.
func isKnownOutput(ns walletdb.ReadWriteBucket, op wire.OutPoint) bool {
	k := CanonicalOutPoint(&op.Hash, op.Index)
	if existsRawUnminedCredit(ns, k) != nil {
		return true
	}
	if existsRawUnspent(ns, k) != nil {
		return true
	}
	return false
}

// LockOutput locks an output to the given ID, preventing it from being
// available for coin selection. The absolute time of the lock's expiration is
// returned. The expiration of the lock can be extended by successive
// invocations of this call.
//
// Outputs can be unlocked before their expiration through `UnlockOutput`.
// Otherwise, they are unlocked lazily through calls which iterate through all
// known outputs, e.g., `Balance`, `UnspentOutputs`.
//
// If the output is not known, ErrUnknownOutput is returned. If the output has
// already been locked to a different ID, then ErrOutputAlreadyLocked is
// returned.
func LockOutput(ns walletdb.ReadWriteBucket, id LockID,
	op wire.OutPoint, duration time.Duration) (time.Time, error) {

	// Make sure the output is known.
	if !isKnownOutput(ns, op) {
		return time.Time{}, ErrUnknownOutput
	}

	// Make sure the output hasn't already been locked to some other ID.
	lockedID, _, isLocked := isLockedOutput(ns, op, time.Now())
	if isLocked && lockedID != id {
		return time.Time{}, ErrOutputAlreadyLocked
	}

	expiry := time.Now().Add(duration)
	if err := lockOutput(ns, id, op, expiry); err != nil {
		return time.Time{}, err
	}

	return expiry, nil
}

// UnlockOutput unlocks an output, allowing it to be available for coin
// selection if it remains unspent. The ID should match the one used to
// originally lock the output.
func UnlockOutput(ns walletdb.ReadWriteBucket, id LockID,
	op wire.OutPoint) error {

	// Make sure the output is known.
	if !isKnownOutput(ns, op) {
		return ErrUnknownOutput
	}

	// If the output has already been unlocked, we can return now.
	lockedID, _, isLocked := isLockedOutput(ns, op, time.Now())
	if !isLocked {
		return nil
	}

	// Make sure the output was locked to the same ID.
	if lockedID != id {
		return ErrOutputUnlockNotAllowed
	}

	return unlockOutput(ns, op)
}

// DeleteExpiredLockedOutputs iterates through all existing locked outputs and
// deletes those which have already expired.
func (s *Store) DeleteExpiredLockedOutputs(ns walletdb.ReadWriteBucket) error {
	// Collect all expired output locks first to remove them later on. This
	// is necessary as deleting while iterating would invalidate the
	// iterator.
	var expiredOutputs []wire.OutPoint
	err := forEachLockedOutput(
		ns, func(op wire.OutPoint, _ LockID, expiration time.Time) {
			if !s.clock.Now().Before(expiration) {
				expiredOutputs = append(expiredOutputs, op)
			}
		},
	)
	if err != nil {
		return err
	}

	for _, op := range expiredOutputs {
		if err := unlockOutput(ns, op); err != nil {
			return err
		}
	}

	return nil
}

// ListLockedOutputs returns a list of objects representing the currently locked
// utxos.
func ListLockedOutputs(ns walletdb.ReadBucket) ([]*LockedOutput,
	error) {

	var outputs []*LockedOutput
	err := forEachLockedOutput(
		ns, func(op wire.OutPoint, id LockID, expiration time.Time) {
			// Skip expired leases. They will be cleaned up with the
			// next call to DeleteExpiredLockedOutputs.
			if !time.Now().Before(expiration) {
				return
			}

			outputs = append(outputs, &LockedOutput{
				Outpoint:   op,
				LockID:     id,
				Expiration: expiration,
			})
		},
	)
	if err != nil {
		return nil, err
	}

	return outputs, nil
}