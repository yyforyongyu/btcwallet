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

// CreateTx atomically records a wallet-scoped transaction row, its
// wallet-owned credits, and any spend edges created by its inputs.
//
// The full write runs inside ExecuteTx so the transaction row, created UTXOs,
// and spent-parent markers are either committed together or not at all.
// Received timestamps are normalized to UTC before insert.
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
				TxStatus:     int64(params.Status),
				ReceivedTime: received,
				IsCoinbase:   isCoinbase,
				TxLabel:      params.Label,
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

// UpdateTxLabel updates only the user-visible label for one wallet-scoped
// transaction.
//
// Block assignment, spend-graph updates, and status transitions are handled by
// dedicated transaction-store paths so label edits cannot mutate wallet state.
func (s *SqliteStore) UpdateTxLabel(ctx context.Context,
	params UpdateTxLabelParams) error {

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

// GetTx retrieves one wallet-scoped transaction snapshot by hash.
//
// The returned TxInfo is rebuilt from normalized SQL columns; missing rows map
// to ErrTxNotFound for the requested wallet/hash pair.
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
		row.BlockHash, row.BlockTimestamp, row.TxStatus, row.TxLabel,
	)
}

// ListTxns lists wallet-scoped transactions using either the confirmed-range
// or unmined-only read path.
//
// The unmined path returns blockless history only, while the confirmed path is
// bounded by the requested height range.
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
			row.BlockHash, row.BlockTimestamp, row.TxStatus, row.TxLabel,
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
			row.TxHash, row.RawTx, row.ReceivedTime, block, row.TxStatus,
			row.TxLabel,
		)
		if err != nil {
			return nil, err
		}

		infos[i] = *info
	}

	return infos, nil
}

// DeleteTx atomically removes one live blockless transaction and restores any
// wallet UTXO rows that it had spent.
//
// DeleteTx is limited to the live unconfirmed set; confirmed rows and terminal
// invalid-history rows remain part of the wallet timeline. The transaction must
// also be a leaf in the local spend graph so the delete cannot detach live
// child spenders from their parent history.
//
//nolint:dupl // Backend-specific sqlc types keep the delete wrappers aligned.
func (s *SqliteStore) DeleteTx(ctx context.Context,
	params DeleteTxParams) error {

	deleteTx := func(qtx *sqlcsqlite.Queries) error {
		meta, err := getDeleteTxMetaSqlite(ctx, qtx, params.WalletID,
			params.Txid)
		if err != nil {
			return err
		}

		err = ensureDeleteLeafSqlite(ctx, qtx, params.WalletID,
			params.Txid, meta.ID)
		if err != nil {
			return err
		}

		_, err = qtx.ClearUtxosSpentByTxID(
			ctx, sqlcsqlite.ClearUtxosSpentByTxIDParams{
				WalletID:    int64(params.WalletID),
				SpentByTxID: sql.NullInt64{Int64: meta.ID, Valid: true},
			},
		)
		if err != nil {
			return fmt.Errorf("clear spent utxos: %w", err)
		}

		_, err = qtx.DeleteUtxosByTxID(
			ctx, sqlcsqlite.DeleteUtxosByTxIDParams{
				WalletID: int64(params.WalletID),
				TxID:     meta.ID,
			},
		)
		if err != nil {
			return fmt.Errorf("delete created utxos: %w", err)
		}

		rows, err := qtx.DeleteUnminedTransactionByHash(
			ctx, sqlcsqlite.DeleteUnminedTransactionByHashParams{
				WalletID: int64(params.WalletID),
				TxHash:   params.Txid[:],
			},
		)
		if err != nil {
			return fmt.Errorf("delete unmined transaction: %w", err)
		}

		if rows == 0 {
			return fmt.Errorf("transaction %s: %w", params.Txid,
				ErrTxNotFound)
		}

		return nil
	}

	return s.ExecuteTx(ctx, deleteTx)
}

// ensureDeleteLeafSqlite rejects DeleteTx requests for transactions that still
// have direct live child spenders, including children that spend non-credit
// parent outputs.
func ensureDeleteLeafSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	walletID uint32, txHash chainhash.Hash, txID int64) error {

	rows, err := qtx.ListUnminedTransactions(ctx, int64(walletID))
	if err != nil {
		return fmt.Errorf("list live transactions: %w", err)
	}

	candidates := make([]liveTxRecord, 0, len(rows))
	for _, row := range rows {
		if row.ID == txID {
			continue
		}

		candidate, err := newLiveTxRecord(row.ID, row.TxHash, row.RawTx)
		if err != nil {
			return fmt.Errorf("decode live transaction %d: %w", row.ID, err)
		}

		candidates = append(candidates, candidate)
	}

	if len(collectDirectChildTxIDs(txHash, candidates)) > 0 {
		return fmt.Errorf("delete transaction %s: %w", txHash,
			errDeleteRequiresLeaf)
	}

	return nil
}

// getDeleteTxMetaSqlite loads the transaction metadata DeleteTx needs and
// enforces the live-unconfirmed precondition up front.
func getDeleteTxMetaSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	walletID uint32, txHash chainhash.Hash) (
	sqlcsqlite.GetTransactionMetaByHashRow, error) {

	meta, err := qtx.GetTransactionMetaByHash(
		ctx, sqlcsqlite.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sqlcsqlite.GetTransactionMetaByHashRow{}, fmt.Errorf(
				"transaction %s: %w", txHash, ErrTxNotFound,
			)
		}

		return sqlcsqlite.GetTransactionMetaByHashRow{}, fmt.Errorf(
			"get transaction metadata: %w", err,
		)
	}

	status, err := parseTxStatus(meta.TxStatus)
	if err != nil {
		return sqlcsqlite.GetTransactionMetaByHashRow{}, err
	}

	if meta.BlockHeight.Valid || !isLiveUnconfirmedStatus(status) {
		return sqlcsqlite.GetTransactionMetaByHashRow{}, fmt.Errorf(
			"delete transaction %s: %w", txHash,
			errDeleteRequiresLiveUnconfirmed,
		)
	}

	return meta, nil
}

// RollbackToBlock atomically removes every block at or above the provided
// height and rewrites wallet sync-state references so the block delete can
// succeed.
//
// The sync-state clamp, descendant invalidation, and block deletion run in one
// transaction so rollback cannot leave dangling references or live descendants
// of disconnected coinbase history.
func (s *SqliteStore) RollbackToBlock(ctx context.Context,
	height uint32) error {

	newHeight := sql.NullInt64{}
	if height > 0 {
		newHeight = sql.NullInt64{Int64: int64(height - 1), Valid: true}
	}

	rollbackBlocks := func(qtx *sqlcsqlite.Queries) error {
		roots, err := qtx.ListRollbackCoinbaseRoots(
			ctx, int64(height),
		)
		if err != nil {
			return fmt.Errorf("list rollback coinbase roots: %w", err)
		}

		rootHashesByWallet, err := groupRollbackCoinbaseRootsSqlite(roots)
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

		err = applyRollbackDescendantInvalidation(
			ctx,
			rootHashesByWallet,
			qtx.ListUnminedTransactions,
			func(row sqlcsqlite.ListUnminedTransactionsRow) (
				int64, []byte, []byte,
			) {

				return row.ID, row.TxHash, row.RawTx
			},
			qtx.ClearUtxosSpentByTxID,
			func(walletID int64,
				descendantID int64) sqlcsqlite.ClearUtxosSpentByTxIDParams {

				return sqlcsqlite.ClearUtxosSpentByTxIDParams{
					WalletID: walletID,
					SpentByTxID: sql.NullInt64{
						Int64: descendantID,
						Valid: true,
					},
				}
			},
			qtx.UpdateTransactionStatusByIDs,
			func(
				walletID int64, descendantIDs []int64,
			) sqlcsqlite.UpdateTransactionStatusByIDsParams {

				return sqlcsqlite.UpdateTransactionStatusByIDsParams{
					WalletID: walletID,
					Status:   int64(TxStatusFailed),
					TxIds:    descendantIDs,
				}
			},
		)
		if err != nil {
			return err
		}

		return nil
	}

	return s.ExecuteTx(ctx, rollbackBlocks)
}

// insertCreditsSqlite inserts one wallet-owned UTXO row for each credited
// output of the transaction being stored.
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

		_, err = qtx.InsertUtxo(ctx, sqlcsqlite.InsertUtxoParams{
			WalletID:    int64(params.WalletID),
			TxID:        txID,
			OutputIndex: int64(credit.Index),
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

// markInputsSpentSqlite attaches wallet-owned outpoints spent by the stored
// transaction to its row ID and input indexes.
//
// If another live wallet transaction already owns the spend edge for a
// wallet-controlled input, the create path fails with ErrTxInputConflict
// instead of silently storing a second live spender.
func markInputsSpentSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	params CreateTxParams, txID int64) error {

	if blockchain.IsCoinBaseTx(params.Tx) {
		return nil
	}

	for inputIndex, txIn := range params.Tx.TxIn {
		spentInputIndex := sql.NullInt64{Int64: int64(inputIndex), Valid: true}

		rowsAffected, err := qtx.MarkUtxoSpent(ctx,
			sqlcsqlite.MarkUtxoSpentParams{
				WalletID:        int64(params.WalletID),
				TxHash:          txIn.PreviousOutPoint.Hash[:],
				OutputIndex:     int64(txIn.PreviousOutPoint.Index),
				SpentByTxID:     sql.NullInt64{Int64: txID, Valid: true},
				SpentInputIndex: spentInputIndex,
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

// groupRollbackCoinbaseRootsSqlite groups rollback-affected coinbase hashes by
// wallet so descendant invalidation can reuse wallet-scoped unmined queries.
func groupRollbackCoinbaseRootsSqlite(
	rows []sqlcsqlite.ListRollbackCoinbaseRootsRow) (
	map[uint32]map[chainhash.Hash]struct{}, error) {

	rootHashesByWallet := make(map[uint32]map[chainhash.Hash]struct{},
		len(rows))

	for _, row := range rows {
		walletID, err := int64ToUint32(row.WalletID)
		if err != nil {
			return nil, fmt.Errorf("rollback coinbase wallet id: %w", err)
		}

		txHash, err := chainhash.NewHash(row.TxHash)
		if err != nil {
			return nil, fmt.Errorf("rollback coinbase hash: %w", err)
		}

		if _, ok := rootHashesByWallet[walletID]; !ok {
			rootHashesByWallet[walletID] = make(map[chainhash.Hash]struct{})
		}

		rootHashesByWallet[walletID][*txHash] = struct{}{}
	}

	return rootHashesByWallet, nil
}

// txInfoFromSqliteRow converts one normalized sqlite query row into the public
// TxInfo shape.
func txInfoFromSqliteRow(hash []byte, rawTx []byte, received time.Time,
	blockHeight sql.NullInt64, blockHash []byte, blockTimestamp sql.NullInt64,
	status int64, label string) (*TxInfo, error) {

	block, err := buildSqliteOptionalBlock(
		blockHeight, blockHash, blockTimestamp,
	)
	if err != nil {
		return nil, err
	}

	return buildTxInfo(
		hash, rawTx, received, block, status, label,
	)
}

// buildSqliteOptionalBlock returns nil for blockless history and otherwise
// converts the sqlite block columns into the public Block shape.
func buildSqliteOptionalBlock(height sql.NullInt64, hash []byte,
	timestamp sql.NullInt64) (*Block, error) {

	if !height.Valid {
		// Nil block is the expected shape for blockless history.
		//nolint:nilnil
		return nil, nil
	}

	return buildSqliteBlock(height, hash, timestamp)
}

// buildSqliteConfirmedBlock converts required sqlite block columns into the
// public Block shape used by confirmed-only read paths.
func buildSqliteConfirmedBlock(height sql.NullInt64, hash []byte,
	timestamp int64) (*Block, error) {

	return buildSqliteBlock(
		height, hash, sql.NullInt64{Int64: timestamp, Valid: true},
	)
}
