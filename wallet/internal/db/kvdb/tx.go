package kvdb

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

// InvalidateUnminedTx invalidates one wallet-owned unmined transaction branch
// through the legacy wtxmgr conflict-removal path.
//
// NOTE: The legacy kvdb backend only supports a single wallet instance, so the
// WalletID field is ignored.
func (s *Store) InvalidateUnminedTx(_ context.Context,
	params db.InvalidateUnminedTxParams) error {

	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return errMissingTxmgrNamespace
		}

		details, err := s.txStore.TxDetails(ns, &params.Txid)
		if err != nil {
			return fmt.Errorf("lookup transaction details: %w", err)
		}

		if details == nil {
			return db.ErrTxNotFound
		}

		if details.Block.Height != -1 ||
			blockchain.IsCoinBaseTx(&details.MsgTx) {

			return db.ErrInvalidateRequiresUnmined
		}

		err = s.txStore.RemoveUnminedTx(ns, &details.TxRecord)
		if err != nil {
			return fmt.Errorf("remove unmined transaction: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.InvalidateUnminedTx: %w", err)
	}

	return nil
}
