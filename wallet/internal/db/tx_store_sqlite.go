package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// Ensure SqliteStore satisfies the TxStore interface.
var _ TxStore = (*SqliteStore)(nil)

// CreateTx atomically records one wallet-scoped transaction row together with
// any wallet-owned credits and spent-input edges derived from the same payload.
// The method normalizes the received timestamp to UTC before writing and keeps
// the transaction row, created UTXOs, and input-spend claims in one SQL
// transaction so readers never observe a partially-applied wallet view.
func (s *SqliteStore) CreateTx(ctx context.Context,
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

	commitTx := func(qtx *sqlcsqlite.Queries) error {
		blockHeight := sql.NullInt64{}
		if params.Block != nil {
			err := ensureBlockExistsSqlite(ctx, qtx, params.Block)
			if err != nil {
				return fmt.Errorf("ensure block exists: %w", err)
			}

			blockHeight = sql.NullInt64{
				Int64: int64(params.Block.Height),
				Valid: true,
			}

			rows, err := qtx.ConfirmUnminedTransactionByHash(
				ctx, sqlcsqlite.ConfirmUnminedTransactionByHashParams{
					WalletID:    int64(params.WalletID),
					TxHash:      txHash[:],
					BlockHeight: int64(params.Block.Height),
				},
			)
			if err != nil {
				return fmt.Errorf("confirm transaction: %w", err)
			}

			if rows > 0 {
				return nil
			}
		}

		txID, err := qtx.InsertTransaction(
			ctx, sqlcsqlite.InsertTransactionParams{
				WalletID:     int64(params.WalletID),
				TxHash:       txHash[:],
				RawTx:        rawTx,
				BlockHeight:  blockHeight,
				Status:       string(params.Status),
				ReceivedTime: received,
				IsCoinbase:   isCoinbase,
				Label:        params.Label,
			},
		)
		if err != nil {
			return fmt.Errorf("insert transaction: %w", err)
		}

		err = insertCreditsSqlite(ctx, qtx, params, txID)
		if err != nil {
			return err
		}

		err = markInputsSpentSqlite(ctx, qtx, params, txID)
		if err != nil {
			return err
		}

		return nil
	}

	return s.ExecuteTx(ctx, commitTx)
}

// UpdateTx updates only the user-visible label for one wallet-scoped
// transaction. It does not modify chain-assignment fields or validity state.
func (s *SqliteStore) UpdateTx(ctx context.Context,
	params UpdateTxParams) error {

	rows, err := s.queries.UpdateTransactionLabelByHash(
		ctx, sqlcsqlite.UpdateTransactionLabelByHashParams{
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
func (s *SqliteStore) GetTx(ctx context.Context,
	query GetTxQuery) (*TxInfo, error) {

	row, err := s.queries.GetTransactionByHash(
		ctx, sqlcsqlite.GetTransactionByHashParams{
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

	return txInfoFromSqliteRow(
		row.TxHash, row.RawTx, row.ReceivedTime, row.BlockHeight,
		row.BlockHash, row.BlockTimestamp, row.Status, row.Label,
	)
}

// ListTxns returns wallet-scoped transaction history using either the confirmed
// height-range query or the blockless history query. The unmined path preserves
// invalid history rows such as `failed`, `replaced`, and orphaned coinbase
// transactions instead of collapsing history to the live mempool set.
func (s *SqliteStore) ListTxns(ctx context.Context,
	query ListTxnsQuery) ([]TxInfo, error) {

	// Unmined rows have no block height, so callers need a dedicated query
	// path.
	// A zero-height range cannot express "return only blockless history".
	if query.UnminedOnly {
		return s.listUnminedTxnsSqlite(ctx, query.WalletID)
	}

	return s.listConfirmedTxnsSqlite(ctx, query)
}

// listUnminedTxnsSqlite loads the blockless transaction view used by ListTxns
// when callers request only unmined history.
func (s *SqliteStore) listUnminedTxnsSqlite(ctx context.Context,
	walletID uint32) ([]TxInfo, error) {

	rows, err := s.queries.ListUnminedTransactions(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf("list unmined transactions: %w", err)
	}

	infos := make([]TxInfo, len(rows))
	for i, row := range rows {
		info, err := txInfoFromSqliteRow(
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

// listConfirmedTxnsSqlite loads the confirmed height-range view used by
// ListTxns when callers query mined history.
func (s *SqliteStore) listConfirmedTxnsSqlite(ctx context.Context,
	query ListTxnsQuery) ([]TxInfo, error) {

	rows, err := s.queries.ListTransactionsByHeightRange(
		ctx, sqlcsqlite.ListTransactionsByHeightRangeParams{
			WalletID:    int64(query.WalletID),
			StartHeight: int64(query.StartHeight),
			EndHeight:   int64(query.EndHeight),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list transactions by height: %w", err)
	}

	infos := make([]TxInfo, len(rows))
	for i, row := range rows {
		block, err := buildSqliteConfirmedBlock(
			row.BlockHeight, row.BlockHash, row.BlockTimestamp,
		)
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
func (s *SqliteStore) DeleteTx(ctx context.Context,
	params DeleteTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		return deleteTxCommon(
			ctx, params.Txid, buildTxDeleteHooksSqlite(qtx, params),
		)
	})
}

// buildTxDeleteHooksSqlite binds the shared delete flow to the sqlite query
// set active for the surrounding SQL transaction.
func buildTxDeleteHooksSqlite(qtx *sqlcsqlite.Queries,
	params DeleteTxParams) txDeleteHooks {

	return buildTxDeleteHooks(
		func(ctx context.Context) (txChainMeta, error) {
			return loadTxChainMetaSqlite(
				ctx, qtx, params.WalletID, params.Txid,
			)
		},
		func(ctx context.Context, txID int64) ([]int64, error) {
			return listDeleteChildTxIDsSqlite(
				ctx, qtx, params.WalletID, params.Txid, txID,
			)
		},
		func(ctx context.Context, txID int64) error {
			return clearSpentByTxIDSqlite(
				ctx, qtx, params.WalletID, txID,
			)
		},
		func(ctx context.Context, txID int64) error {
			return deleteUtxosByTxIDSqlite(
				ctx, qtx, params.WalletID, txID,
			)
		},
		func(ctx context.Context) (int64, error) {
			return deleteUnminedTxByHashSqlite(
				ctx, qtx, params.WalletID, params.Txid,
			)
		},
	)
}

// listDeleteChildTxIDsSqlite returns the direct live child spenders of one
// parent transaction, including children that spend non-credit parent outputs.
func listDeleteChildTxIDsSqlite(ctx context.Context,
	qtx *sqlcsqlite.Queries, walletID uint32, txHash chainhash.Hash,
	txID int64) ([]int64, error) {

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

// deleteUtxosByTxIDSqlite removes the wallet-owned outputs created by one
// transaction before its row is pruned from the live graph.
func deleteUtxosByTxIDSqlite(ctx context.Context,
	qtx *sqlcsqlite.Queries, walletID uint32, txID int64) error {

	_, err := qtx.DeleteUtxosByTxID(
		ctx, sqlcsqlite.DeleteUtxosByTxIDParams{
			WalletID: int64(walletID),
			TxID:     txID,
		},
	)
	if err != nil {
		return fmt.Errorf("delete created utxos: %w", err)
	}

	return nil
}

// deleteUnminedTxByHashSqlite removes the unconfirmed transaction row after
// its dependent UTXO edges have already been cleared.
func deleteUnminedTxByHashSqlite(ctx context.Context,
	qtx *sqlcsqlite.Queries, walletID uint32, txid [32]byte) (int64, error) {

	rows, err := qtx.DeleteUnminedTransactionByHash(
		ctx, sqlcsqlite.DeleteUnminedTransactionByHashParams{
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
func (s *SqliteStore) RollbackToBlock(ctx context.Context,
	height uint32) error {

	newHeight := sql.NullInt64{}
	if height > 0 {
		newHeight = sql.NullInt64{Int64: int64(height - 1), Valid: true}
	}

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		orphanRoots, err := listRollbackOrphanRootsSqlite(
			ctx, qtx, int64(height),
		)
		if err != nil {
			return err
		}

		_, err = qtx.RewindWalletSyncStateHeightsForRollback(
			ctx, sqlcsqlite.RewindWalletSyncStateHeightsForRollbackParams{
				RollbackHeight: int64(height),
				NewHeight:      newHeight,
			},
		)
		if err != nil {
			return fmt.Errorf("rewind wallet sync state heights: %w", err)
		}

		_, err = qtx.DeleteBlocksAtOrAboveHeight(ctx, int64(height))
		if err != nil {
			return fmt.Errorf("delete blocks at or above height: %w", err)
		}

		err = applyRollbackOrphanInvalidation(
			ctx, orphanRoots,
			func(walletID uint32) txChainHooks {
				return buildTxChainHooksSqlite(qtx, walletID)
			},
		)
		if err != nil {
			return fmt.Errorf("apply rollback orphan invalidation: %w", err)
		}

		return nil
	})
}

// listRollbackOrphanRootsSqlite resolves the confirmed coinbase rows that will
// become orphan roots when rollback deletes the target block range.
func listRollbackOrphanRootsSqlite(ctx context.Context,
	qtx *sqlcsqlite.Queries,
	rollbackHeight int64) ([]rollbackOrphanRoot, error) {

	rows, err := qtx.ListCoinbaseRollbackRootsAtOrAboveHeight(
		ctx, sql.NullInt64{Int64: rollbackHeight, Valid: true},
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

// insertCreditsSqlite resolves each credited wallet output by script and
// inserts the corresponding UTXO rows inside the surrounding CreateTx
// transaction.
func insertCreditsSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	params CreateTxParams, txID int64) error {

	for _, credit := range params.Credits {
		pkScript := params.Tx.TxOut[credit.Index].PkScript

		addrRow, err := qtx.GetAddressByScriptPubKey(
			ctx, sqlcsqlite.GetAddressByScriptPubKeyParams{
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

		_, err = qtx.InsertUtxo(ctx, sqlcsqlite.InsertUtxoParams{
			WalletID:    int64(params.WalletID),
			TxID:        txID,
			OutputIndex: int64(outputIndex),
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

// markInputsSpentSqlite records the new spender on any wallet-owned inputs used
// by the transaction being inserted.
func markInputsSpentSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
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

		rowsAffected, err := qtx.MarkUtxoSpent(ctx,
			sqlcsqlite.MarkUtxoSpentParams{
				WalletID:    int64(params.WalletID),
				TxHash:      txIn.PreviousOutPoint.Hash[:],
				OutputIndex: int64(outputIndex),
				SpentByTxID: sql.NullInt64{Int64: txID, Valid: true},
				SpentInputIndex: sql.NullInt64{
					Int64: int64(spentInputIndex),
					Valid: true,
				},
			})
		if err != nil {
			return fmt.Errorf("mark spent input %d: %w", inputIndex, err)
		}

		if rowsAffected == 0 {
			err = ensureSpendConflictSqlite(
				ctx, qtx, params.WalletID, txIn.PreviousOutPoint.Hash,
				int64(txIn.PreviousOutPoint.Index), txID,
			)
			if err != nil {
				return fmt.Errorf("mark spent input %d: %w", inputIndex,
					err)
			}
		}
	}

	return nil
}

// ensureSpendConflictSqlite reports ErrTxInputConflict when the referenced
// outpoint is wallet-owned, still eligible for spending, and already attached
// to another transaction.
func ensureSpendConflictSqlite(ctx context.Context,
	qtx *sqlcsqlite.Queries, walletID uint32, txHash chainhash.Hash,
	outputIndex int64, txID int64) error {

	spendByTxID, err := qtx.GetUtxoSpendByOutpoint(
		ctx, sqlcsqlite.GetUtxoSpendByOutpointParams{
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

// txInfoFromSqliteRow maps one sqlite query row into the public TxInfo
// contract, including optional block metadata.
func txInfoFromSqliteRow(hash []byte, rawTx []byte, received time.Time,
	blockHeight sql.NullInt64, blockHash []byte, blockTimestamp sql.NullInt64,
	status string, label string) (*TxInfo, error) {

	block, _, err := buildSqliteOptionalBlock(
		blockHeight, blockHash, blockTimestamp,
	)
	if err != nil {
		return nil, err
	}

	return buildTxInfo(
		hash, rawTx, received, block, status, label,
	)
}

// buildSqliteOptionalBlock converts nullable sqlite block columns into an
// optional public Block and reports whether a confirmation block was present.
func buildSqliteOptionalBlock(height sql.NullInt64, hash []byte,
	timestamp sql.NullInt64) (*Block, bool, error) {

	if !height.Valid {
		return nil, false, nil
	}

	block, err := buildSqliteBlock(height, hash, timestamp)
	if err != nil {
		return nil, false, err
	}

	return block, true, nil
}

// buildSqliteConfirmedBlock converts required sqlite block columns into the
// public Block shape used by confirmed-only read paths.
func buildSqliteConfirmedBlock(height sql.NullInt64, hash []byte,
	timestamp int64) (*Block, error) {

	return buildSqliteBlock(
		height, hash, sql.NullInt64{Int64: timestamp, Valid: true},
	)
}
