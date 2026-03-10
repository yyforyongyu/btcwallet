package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// Ensure PostgresStore satisfies the TxStore interface.
var _ TxStore = (*PostgresStore)(nil)

// CreateTx atomically records one wallet-scoped transaction row together with
// any wallet-owned credits and spent-input edges derived from the same payload.
// The method normalizes the received timestamp to UTC before writing and keeps
// the transaction row, created UTXOs, and input-spend claims in one SQL
// transaction so readers never observe a partially-applied wallet view.
func (s *PostgresStore) CreateTx(ctx context.Context,
	params CreateTxParams) error {

	err := validateCreateTxParams(params)
	if err != nil {
		return fmt.Errorf("validate create tx params: %w", err)
	}

	rawTx, err := serializeMsgTx(params.Tx)
	if err != nil {
		return err
	}

	txHash := params.Tx.TxHash()
	isCoinbase := blockchain.IsCoinBaseTx(params.Tx)
	received := params.Received.UTC()

	commitTx := func(qtx *sqlcpg.Queries) error {
		blockHeight, confirmedExisting, err := prepareCreateTxBlockHeightPg(
			ctx, qtx, params.WalletID, txHash, params.Block,
		)
		if err != nil {
			return err
		}

		if confirmedExisting {
			return nil
		}

		txID, err := qtx.InsertTransaction(ctx, sqlcpg.InsertTransactionParams{
			WalletID:     int64(params.WalletID),
			TxHash:       txHash[:],
			RawTx:        rawTx,
			BlockHeight:  blockHeight,
			Status:       string(params.Status),
			ReceivedTime: received,
			IsCoinbase:   isCoinbase,
			Label:        params.Label,
		})
		if err != nil {
			return fmt.Errorf("insert transaction: %w", err)
		}

		err = insertCreditsPg(ctx, qtx, params, txID)
		if err != nil {
			return err
		}

		err = markInputsSpentPg(ctx, qtx, params, txID)
		if err != nil {
			return err
		}

		return nil
	}

	return s.ExecuteTx(ctx, commitTx)
}

// prepareCreateTxBlockHeightPg resolves the optional confirming block height
// and attaches it to an existing live unmined transaction when possible.
func prepareCreateTxBlockHeightPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txHash chainhash.Hash,
	block *Block) (sql.NullInt32, bool, error) {

	if block == nil {
		return sql.NullInt32{}, false, nil
	}

	err := ensureBlockExistsPg(ctx, qtx, block)
	if err != nil {
		return sql.NullInt32{}, false,
			fmt.Errorf("ensure block exists: %w", err)
	}

	height, err := uint32ToInt32(block.Height)
	if err != nil {
		return sql.NullInt32{}, false,
			fmt.Errorf("convert block height: %w", err)
	}

	blockHeight := sql.NullInt32{Int32: height, Valid: true}

	rows, err := qtx.ConfirmUnminedTransactionByHash(
		ctx, sqlcpg.ConfirmUnminedTransactionByHashParams{
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
			BlockHeight: height,
		},
	)
	if err != nil {
		return sql.NullInt32{}, false,
			fmt.Errorf("confirm transaction: %w", err)
	}

	return blockHeight, rows > 0, nil
}

// UpdateTx updates only the user-visible label for one wallet-scoped
// transaction. It does not modify chain-assignment fields or validity state.
func (s *PostgresStore) UpdateTx(ctx context.Context,
	params UpdateTxParams) error {

	rows, err := s.queries.UpdateTransactionLabelByHash(
		ctx, sqlcpg.UpdateTransactionLabelByHashParams{
			Label:    params.Label,
			WalletID: int64(params.WalletID),
			TxHash:   params.Txid[:],
		},
	)
	if err != nil {
		return fmt.Errorf("update transaction label: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("transaction %s: %w", params.Txid, ErrTxNotFound)
	}

	return nil
}

// GetTx retrieves one wallet-scoped transaction by hash and maps the stored row
// into the public TxInfo contract, including optional block metadata.
func (s *PostgresStore) GetTx(ctx context.Context,
	query GetTxQuery) (*TxInfo, error) {

	row, err := s.queries.GetTransactionByHash(
		ctx, sqlcpg.GetTransactionByHashParams{
			WalletID: int64(query.WalletID),
			TxHash:   query.Txid[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("transaction %s: %w", query.Txid,
				ErrTxNotFound)
		}

		return nil, fmt.Errorf("get transaction: %w", err)
	}

	return txInfoFromPgRow(
		row.TxHash, row.RawTx, row.ReceivedTime, row.BlockHeight,
		row.BlockHash, row.BlockTimestamp, row.Status, row.Label,
	)
}

// ListTxns returns wallet-scoped transaction history using either the confirmed
// height-range query or the blockless history query. The unmined path preserves
// invalid history rows such as `failed`, `replaced`, and orphaned coinbase
// transactions instead of collapsing history to the live mempool set.
func (s *PostgresStore) ListTxns(ctx context.Context,
	query ListTxnsQuery) ([]TxInfo, error) {

	// Unmined rows have no block height, so callers need a dedicated query
	// path.
	// A zero-height range cannot express "return only blockless history".
	if query.UnminedOnly {
		return s.listUnminedTxnsPg(ctx, query.WalletID)
	}

	return s.listConfirmedTxnsPg(ctx, query)
}

// listUnminedTxnsPg returns every wallet-scoped blockless transaction row,
// including invalid history states that must remain visible to history reads.
func (s *PostgresStore) listUnminedTxnsPg(ctx context.Context,
	walletID uint32) ([]TxInfo, error) {

	rows, err := s.queries.ListUnminedTransactions(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf("list unmined transactions: %w", err)
	}

	infos := make([]TxInfo, len(rows))
	for i, row := range rows {
		info, err := txInfoFromPgRow(
			row.TxHash, row.RawTx, row.ReceivedTime, row.BlockHeight,
			row.BlockHash, row.BlockTimestamp, row.Status, row.Label,
		)
		if err != nil {
			return nil, err
		}

		infos[i] = *info
	}

	return infos, nil
}

// listConfirmedTxnsPg returns the confirmed transaction rows whose block
// heights fall within the inclusive caller-provided range.
func (s *PostgresStore) listConfirmedTxnsPg(ctx context.Context,
	query ListTxnsQuery) ([]TxInfo, error) {

	startHeight, err := uint32ToInt32(query.StartHeight)
	if err != nil {
		return nil, fmt.Errorf("convert start height: %w", err)
	}

	endHeight, err := uint32ToInt32(query.EndHeight)
	if err != nil {
		return nil, fmt.Errorf("convert end height: %w", err)
	}

	rows, err := s.queries.ListTransactionsByHeightRange(
		ctx, sqlcpg.ListTransactionsByHeightRangeParams{
			WalletID:    int64(query.WalletID),
			StartHeight: startHeight,
			EndHeight:   endHeight,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list transactions by height: %w", err)
	}

	infos := make([]TxInfo, len(rows))
	for i, row := range rows {
		block, err := buildPgConfirmedBlock(row.BlockHeight, row.BlockHash,
			row.BlockTimestamp)
		if err != nil {
			return nil, err
		}

		info, err := buildTxInfo(
			row.TxHash, row.RawTx, row.ReceivedTime, block, row.Status,
			row.Label,
		)
		if err != nil {
			return nil, err
		}

		infos[i] = *info
	}

	return infos, nil
}

// DeleteTx atomically removes one live unconfirmed leaf transaction after
// verifying it has no wallet-scoped descendants. The surrounding SQL
// transaction restores any wallet-owned inputs claimed by the deleted row
// before pruning the row itself.
func (s *PostgresStore) DeleteTx(ctx context.Context,
	params DeleteTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		return deleteTxCommon(
			ctx, params.Txid, buildTxDeleteHooksPg(qtx, params),
		)
	})
}

// buildTxDeleteHooksPg binds the shared delete flow to the postgres query set
// active for the surrounding SQL transaction.
func buildTxDeleteHooksPg(qtx *sqlcpg.Queries,
	params DeleteTxParams) txDeleteHooks {

	return buildTxDeleteHooks(
		func(ctx context.Context) (txChainMeta, error) {
			return loadTxChainMetaPg(ctx, qtx, params.WalletID, params.Txid)
		},
		func(ctx context.Context, txID int64) ([]int64, error) {
			return listDeleteChildTxIDsPg(
				ctx, qtx, params.WalletID, params.Txid, txID,
			)
		},
		func(ctx context.Context, txID int64) error {
			return clearSpentByTxIDPg(ctx, qtx, params.WalletID, txID)
		},
		func(ctx context.Context, txID int64) error {
			return deleteUtxosByTxIDPg(ctx, qtx, params.WalletID, txID)
		},
		func(ctx context.Context) (int64, error) {
			return deleteUnminedTxByHashPg(
				ctx, qtx, params.WalletID, params.Txid,
			)
		},
	)
}

// listDeleteChildTxIDsPg returns the direct live child spenders of one parent
// transaction, including children that spend non-credit parent outputs.
func listDeleteChildTxIDsPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txHash chainhash.Hash, txID int64) ([]int64, error) {

	rows, err := qtx.ListUnminedTransactions(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf("list live transactions: %w", err)
	}

	candidates := make([]liveTxRecord, 0, len(rows))
	for _, row := range rows {
		if row.ID == txID {
			continue
		}

		candidate, err := newLiveTxRecord(row.ID, row.TxHash, row.RawTx)
		if err != nil {
			return nil, fmt.Errorf("decode live transaction %d: %w", row.ID,
				err)
		}

		candidates = append(candidates, candidate)
	}

	return collectDirectChildTxIDs(txHash, candidates), nil
}

// deleteUtxosByTxIDPg removes the wallet-owned outputs created by one
// transaction before its row is pruned from the live graph.
func deleteUtxosByTxIDPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txID int64) error {

	_, err := qtx.DeleteUtxosByTxID(
		ctx, sqlcpg.DeleteUtxosByTxIDParams{
			WalletID: int64(walletID),
			TxID:     txID,
		},
	)
	if err != nil {
		return fmt.Errorf("delete created utxos: %w", err)
	}

	return nil
}

// deleteUnminedTxByHashPg removes the unconfirmed transaction row after its
// dependent UTXO edges have already been cleared.
func deleteUnminedTxByHashPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txid [32]byte) (int64, error) {

	rows, err := qtx.DeleteUnminedTransactionByHash(
		ctx, sqlcpg.DeleteUnminedTransactionByHashParams{
			WalletID: int64(walletID),
			TxHash:   txid[:],
		},
	)
	if err != nil {
		return 0, fmt.Errorf("delete unmined transaction: %w", err)
	}

	return rows, nil
}

// RollbackToBlock atomically disconnects every block at or above the provided
// height. It rewrites wallet sync-state references, snapshots coinbase roots
// that will become orphaned, deletes the blocks, and then recursively fails any
// descendant branch that depended on those roots before commit.
func (s *PostgresStore) RollbackToBlock(ctx context.Context,
	height uint32) error {

	rollbackHeight, err := uint32ToInt32(height)
	if err != nil {
		return fmt.Errorf("convert rollback height: %w", err)
	}

	newHeight := sql.NullInt32{}
	if height > 0 {
		clampedHeight, err := uint32ToInt32(height - 1)
		if err != nil {
			return fmt.Errorf("convert new height: %w", err)
		}

		newHeight = sql.NullInt32{Int32: clampedHeight, Valid: true}
	}

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		orphanRoots, err := listRollbackOrphanRootsPg(
			ctx, qtx, rollbackHeight,
		)
		if err != nil {
			return err
		}

		_, err = qtx.RewindWalletSyncStateHeightsForRollback(
			ctx, sqlcpg.RewindWalletSyncStateHeightsForRollbackParams{
				RollbackHeight: rollbackHeight,
				NewHeight:      newHeight,
			},
		)
		if err != nil {
			return fmt.Errorf("rewind wallet sync state heights: %w", err)
		}

		_, err = qtx.DeleteBlocksAtOrAboveHeight(ctx, rollbackHeight)
		if err != nil {
			return fmt.Errorf("delete blocks at or above height: %w", err)
		}

		err = applyRollbackOrphanInvalidation(
			ctx, orphanRoots,
			func(walletID uint32) txChainHooks {
				return buildTxChainHooksPg(qtx, walletID)
			},
		)
		if err != nil {
			return fmt.Errorf("apply rollback orphan invalidation: %w", err)
		}

		return nil
	})
}

// listRollbackOrphanRootsPg resolves the confirmed coinbase rows that will
// become orphan roots when rollback deletes the target block range.
func listRollbackOrphanRootsPg(ctx context.Context, qtx *sqlcpg.Queries,
	rollbackHeight int32) ([]rollbackOrphanRoot, error) {

	rows, err := qtx.ListCoinbaseRollbackRootsAtOrAboveHeight(
		ctx, sql.NullInt32{Int32: rollbackHeight, Valid: true},
	)
	if err != nil {
		return nil, fmt.Errorf("list rollback orphan roots: %w", err)
	}

	roots := make([]rollbackOrphanRoot, 0, len(rows))
	for _, row := range rows {
		walletID, err := int64ToUint32(row.WalletID)
		if err != nil {
			return nil, fmt.Errorf("convert rollback orphan wallet id: %w",
				err)
		}

		roots = append(roots, rollbackOrphanRoot{
			WalletID: walletID,
			TxID:     row.ID,
		})
	}

	return roots, nil
}

// insertCreditsPg resolves each credited wallet output by script and inserts
// the corresponding UTXO rows inside the surrounding CreateTx transaction.
func insertCreditsPg(ctx context.Context, qtx *sqlcpg.Queries,
	params CreateTxParams, txID int64) error {

	for _, credit := range params.Credits {
		pkScript := params.Tx.TxOut[credit.Index].PkScript

		addrRow, err := qtx.GetAddressByScriptPubKey(
			ctx, sqlcpg.GetAddressByScriptPubKeyParams{
				ScriptPubKey: pkScript,
				WalletID:     int64(params.WalletID),
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("credit output %d: %w", credit.Index,
					ErrAddressNotFound)
			}

			return fmt.Errorf("resolve credit address %d: %w", credit.Index,
				err)
		}

		outputIndex, err := uint32ToInt32(credit.Index)
		if err != nil {
			return fmt.Errorf("convert credit index %d: %w", credit.Index,
				err)
		}

		_, err = qtx.InsertUtxo(ctx, sqlcpg.InsertUtxoParams{
			WalletID:    int64(params.WalletID),
			TxID:        txID,
			OutputIndex: outputIndex,
			Amount:      params.Tx.TxOut[credit.Index].Value,
			AddressID:   addrRow.ID,
		})
		if err != nil {
			return fmt.Errorf("insert credit output %d: %w", credit.Index,
				err)
		}
	}

	return nil
}

// markInputsSpentPg records the new spender on any wallet-owned inputs used by
// the transaction being inserted.
func markInputsSpentPg(ctx context.Context, qtx *sqlcpg.Queries,
	params CreateTxParams, txID int64) error {

	if blockchain.IsCoinBaseTx(params.Tx) {
		return nil
	}

	for inputIndex, txIn := range params.Tx.TxIn {
		outputIndex, err := uint32ToInt32(txIn.PreviousOutPoint.Index)
		if err != nil {
			return fmt.Errorf("convert input outpoint index %d: %w",
				inputIndex, err)
		}

		spentInputIndex, err := intToInt32(inputIndex)
		if err != nil {
			return fmt.Errorf("convert input index %d: %w", inputIndex, err)
		}

		rowsAffected, err := qtx.MarkUtxoSpent(
			ctx, sqlcpg.MarkUtxoSpentParams{
				WalletID:    int64(params.WalletID),
				TxHash:      txIn.PreviousOutPoint.Hash[:],
				OutputIndex: outputIndex,
				SpentByTxID: sql.NullInt64{Int64: txID, Valid: true},
				SpentInputIndex: sql.NullInt32{
					Int32: spentInputIndex,
					Valid: true,
				},
			},
		)
		if err != nil {
			return fmt.Errorf("mark spent input %d: %w", inputIndex, err)
		}

		if rowsAffected == 0 {
			err = ensureSpendConflictPg(
				ctx, qtx, params.WalletID, txIn.PreviousOutPoint.Hash,
				outputIndex, txID,
			)
			if err != nil {
				return fmt.Errorf("mark spent input %d: %w", inputIndex,
					err)
			}
		}
	}

	return nil
}

// ensureSpendConflictPg reports ErrTxInputConflict when the referenced outpoint
// is wallet-owned, still eligible for spending, and already attached to another
// transaction.
func ensureSpendConflictPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txHash chainhash.Hash, outputIndex int32,
	txID int64) error {

	spendByTxID, err := qtx.GetUtxoSpendByOutpoint(
		ctx, sqlcpg.GetUtxoSpendByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
			OutputIndex: outputIndex,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}

		return fmt.Errorf("check spend conflict: %w", err)
	}

	if spendByTxID.Valid && spendByTxID.Int64 != txID {
		return ErrTxInputConflict
	}

	return nil
}

// txInfoFromPgRow maps one postgres query row into the public TxInfo contract,
// including optional block metadata.
func txInfoFromPgRow(hash []byte, rawTx []byte, received time.Time,
	blockHeight sql.NullInt32, blockHash []byte, blockTimestamp sql.NullInt64,
	status string, label string) (*TxInfo, error) {

	block, _, err := buildPgOptionalBlock(
		blockHeight, blockHash, blockTimestamp,
	)
	if err != nil {
		return nil, err
	}

	return buildTxInfo(
		hash, rawTx, received, block, status, label,
	)
}

// buildPgOptionalBlock converts nullable postgres block columns into an
// optional public Block and reports whether a confirmation block was present.
func buildPgOptionalBlock(height sql.NullInt32, hash []byte,
	timestamp sql.NullInt64) (*Block, bool, error) {

	if !height.Valid {
		return nil, false, nil
	}

	block, err := buildPgBlock(height, hash, timestamp)
	if err != nil {
		return nil, false, err
	}

	return block, true, nil
}

// buildPgConfirmedBlock converts required postgres block columns into the
// public Block shape used by confirmed-only read paths.
func buildPgConfirmedBlock(height sql.NullInt32, hash []byte,
	timestamp int64) (*Block, error) {

	return buildPgBlock(
		height, hash, sql.NullInt64{Int64: timestamp, Valid: true},
	)
}
