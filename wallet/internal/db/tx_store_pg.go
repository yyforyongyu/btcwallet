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

// CreateTx atomically records a wallet-scoped transaction row, its
// wallet-owned credits, and any spend edges created by its inputs.
//
// The full write runs inside ExecuteTx so the transaction row, created UTXOs,
// and spent-parent markers are either committed together or not at all.
// Received timestamps are normalized to UTC before insert.
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
			TxStatus:     int16(params.Status),
			ReceivedTime: received,
			IsCoinbase:   isCoinbase,
			TxLabel:      params.Label,
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

// UpdateTxLabel updates only the user-visible label for one wallet-scoped
// transaction.
//
// Block assignment, spend-graph updates, and status transitions are handled by
// dedicated transaction-store paths so label edits cannot mutate wallet state.
func (s *PostgresStore) UpdateTxLabel(ctx context.Context,
	params UpdateTxLabelParams) error {

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

// GetTx retrieves one wallet-scoped transaction snapshot by hash.
//
// The returned TxInfo is rebuilt from normalized SQL columns; missing rows map
// to ErrTxNotFound for the requested wallet/hash pair.
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
		row.BlockHash, row.BlockTimestamp, int64(row.TxStatus), row.TxLabel,
	)
}

// ListTxns lists wallet-scoped transactions using either the confirmed-range
// or unmined-only read path.
//
// The unmined path returns blockless history only, while the confirmed path is
// bounded by the requested height range.
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

// listUnminedTxnsPg loads the blockless transaction view used by ListTxns when
// callers request only unmined history.
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
			row.BlockHash, row.BlockTimestamp, int64(row.TxStatus), row.TxLabel,
		)
		if err != nil {
			return nil, err
		}

		infos[i] = *info
	}

	return infos, nil
}

// listConfirmedTxnsPg loads the confirmed height-range view used by ListTxns
// when callers query mined history.
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
			row.TxHash, row.RawTx, row.ReceivedTime, block,
			int64(row.TxStatus), row.TxLabel,
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
func (s *PostgresStore) DeleteTx(ctx context.Context,
	params DeleteTxParams) error {

	deleteTx := func(qtx *sqlcpg.Queries) error {
		meta, err := getDeleteTxMetaPg(ctx, qtx, params.WalletID,
			params.Txid)
		if err != nil {
			return err
		}

		err = ensureDeleteLeafPg(ctx, qtx, params.WalletID, params.Txid,
			meta.ID)
		if err != nil {
			return err
		}

		_, err = qtx.ClearUtxosSpentByTxID(
			ctx, sqlcpg.ClearUtxosSpentByTxIDParams{
				WalletID:    int64(params.WalletID),
				SpentByTxID: sql.NullInt64{Int64: meta.ID, Valid: true},
			},
		)
		if err != nil {
			return fmt.Errorf("clear spent utxos: %w", err)
		}

		_, err = qtx.DeleteUtxosByTxID(
			ctx, sqlcpg.DeleteUtxosByTxIDParams{
				WalletID: int64(params.WalletID),
				TxID:     meta.ID,
			},
		)
		if err != nil {
			return fmt.Errorf("delete created utxos: %w", err)
		}

		rows, err := qtx.DeleteUnminedTransactionByHash(
			ctx, sqlcpg.DeleteUnminedTransactionByHashParams{
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

// ensureDeleteLeafPg rejects DeleteTx requests for transactions that still have
// direct live child spenders, including children that spend non-credit parent
// outputs.
func ensureDeleteLeafPg(ctx context.Context, qtx *sqlcpg.Queries,
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

// getDeleteTxMetaPg loads the transaction metadata DeleteTx needs and enforces
// the live-unconfirmed precondition up front.
func getDeleteTxMetaPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txHash chainhash.Hash) (sqlcpg.GetTransactionMetaByHashRow,
	error) {

	meta, err := qtx.GetTransactionMetaByHash(
		ctx, sqlcpg.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sqlcpg.GetTransactionMetaByHashRow{}, fmt.Errorf(
				"transaction %s: %w", txHash, ErrTxNotFound,
			)
		}

		return sqlcpg.GetTransactionMetaByHashRow{}, fmt.Errorf(
			"get transaction metadata: %w", err,
		)
	}

	status, err := parseTxStatus(int64(meta.TxStatus))
	if err != nil {
		return sqlcpg.GetTransactionMetaByHashRow{}, err
	}

	if meta.BlockHeight.Valid || !isLiveUnconfirmedStatus(status) {
		return sqlcpg.GetTransactionMetaByHashRow{}, fmt.Errorf(
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

	rollbackBlocks := func(qtx *sqlcpg.Queries) error {
		roots, err := qtx.ListRollbackCoinbaseRoots(ctx, rollbackHeight)
		if err != nil {
			return fmt.Errorf("list rollback coinbase roots: %w", err)
		}

		rootHashesByWallet, err := groupRollbackCoinbaseRootsPg(roots)
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

		err = applyRollbackDescendantInvalidation(
			ctx,
			rootHashesByWallet,
			qtx.ListUnminedTransactions,
			func(row sqlcpg.ListUnminedTransactionsRow) (
				int64, []byte, []byte,
			) {

				return row.ID, row.TxHash, row.RawTx
			},
			qtx.ClearUtxosSpentByTxID,
			func(walletID int64,
				descendantID int64) sqlcpg.ClearUtxosSpentByTxIDParams {

				return sqlcpg.ClearUtxosSpentByTxIDParams{
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
			) sqlcpg.UpdateTransactionStatusByIDsParams {

				return sqlcpg.UpdateTransactionStatusByIDsParams{
					WalletID: walletID,
					Status:   int16(TxStatusFailed),
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

// insertCreditsPg inserts one wallet-owned UTXO row for each credited output of
// the transaction being stored.
func insertCreditsPg(ctx context.Context, qtx *sqlcpg.Queries,
	params CreateTxParams, txID int64) error {

	for index := range params.Credits {
		pkScript := params.Tx.TxOut[index].PkScript

		addrRow, err := qtx.GetAddressByScriptPubKey(
			ctx, sqlcpg.GetAddressByScriptPubKeyParams{
				ScriptPubKey: pkScript,
				WalletID:     int64(params.WalletID),
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("credit output %d: %w", index,
					ErrAddressNotFound)
			}

			return fmt.Errorf("resolve credit address %d: %w", index,
				err)
		}

		outputIndex, err := uint32ToInt32(index)
		if err != nil {
			return fmt.Errorf("convert credit index %d: %w", index,
				err)
		}

		_, err = qtx.InsertUtxo(ctx, sqlcpg.InsertUtxoParams{
			WalletID:    int64(params.WalletID),
			TxID:        txID,
			OutputIndex: outputIndex,
			Amount:      params.Tx.TxOut[index].Value,
			AddressID:   addrRow.ID,
		})
		if err != nil {
			return fmt.Errorf("insert credit output %d: %w", index,
				err)
		}
	}

	return nil
}

// markInputsSpentPg attaches wallet-owned outpoints spent by the stored
// transaction to its row ID and input indexes.
//
// If another live wallet transaction already owns the spend edge for a
// wallet-controlled input, the create path fails with ErrTxInputConflict
// instead of silently storing a second live spender. Inputs that reference a
// dead wallet parent fail with ErrTxInputDeadWalletParent.
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

		spentInputIndex, err := int64ToInt32(int64(inputIndex))
		if err != nil {
			return fmt.Errorf("convert input index %d: %w", inputIndex, err)
		}

		rowsAffected, err := qtx.MarkUtxoSpent(ctx, sqlcpg.MarkUtxoSpentParams{
			WalletID:        int64(params.WalletID),
			TxHash:          txIn.PreviousOutPoint.Hash[:],
			OutputIndex:     outputIndex,
			SpentByTxID:     sql.NullInt64{Int64: txID, Valid: true},
			SpentInputIndex: sql.NullInt32{Int32: spentInputIndex, Valid: true},
		})
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
// transaction. If the wallet owns the parent output but that parent is already
// dead, the helper returns ErrTxInputDeadWalletParent instead.
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
			return ensureWalletParentLivePg(
				ctx, qtx, walletID, txHash, outputIndex,
			)
		}

		return fmt.Errorf("check spend conflict: %w", err)
	}

	if spendByTxID.Valid && spendByTxID.Int64 != txID {
		return ErrTxInputConflict
	}

	return nil
}

// ensureWalletParentLivePg reports ErrTxInputDeadWalletParent when the wallet
// owns the referenced outpoint but its parent transaction is already dead.
func ensureWalletParentLivePg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txHash chainhash.Hash, outputIndex int32) error {

	_, err := qtx.HasDeadWalletUtxoByOutpoint(
		ctx, sqlcpg.HasDeadWalletUtxoByOutpointParams{
			WalletID:    int64(walletID),
			TxHash:      txHash[:],
			OutputIndex: outputIndex,
		},
	)
	if err == nil {
		return ErrTxInputDeadWalletParent
	}

	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}

	return fmt.Errorf("check dead wallet parent: %w", err)
}

// groupRollbackCoinbaseRootsPg groups rollback-affected coinbase hashes by
// wallet so descendant invalidation can reuse wallet-scoped unmined queries.
func groupRollbackCoinbaseRootsPg(rows []sqlcpg.ListRollbackCoinbaseRootsRow) (
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

// txInfoFromPgRow converts one normalized postgres query row into the public
// TxInfo shape.
func txInfoFromPgRow(hash []byte, rawTx []byte, received time.Time,
	blockHeight sql.NullInt32, blockHash []byte, blockTimestamp sql.NullInt64,
	status int64, label string) (*TxInfo, error) {

	block, err := buildPgOptionalBlock(blockHeight, blockHash, blockTimestamp)
	if err != nil {
		return nil, err
	}

	return buildTxInfo(
		hash, rawTx, received, block, status, label,
	)
}

// buildPgOptionalBlock returns nil for blockless history and otherwise converts
// the postgres block columns into the public Block shape.
func buildPgOptionalBlock(height sql.NullInt32, hash []byte,
	timestamp sql.NullInt64) (*Block, error) {

	if !height.Valid {
		// Nil block is the expected shape for blockless history.
		//nolint:nilnil
		return nil, nil
	}

	return buildPgBlock(height, hash, timestamp)
}

// buildPgConfirmedBlock converts required postgres block columns into the
// public Block shape used by confirmed-only read paths.
func buildPgConfirmedBlock(height sql.NullInt32, hash []byte,
	timestamp int64) (*Block, error) {

	return buildPgBlock(
		height, hash, sql.NullInt64{Int64: timestamp, Valid: true},
	)
}
