// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// TxWriter provides an interface for updating wallet txns.
type TxWriter interface {
	// LabelTransaction adds a label to a tx.
	LabelTransaction(hash chainhash.Hash, label string, overwrite bool) error
}

// A compile time check to ensure that Wallet implements the interface.
var _ TxWriter = (*Wallet)(nil)

// LabelTransaction adds a label to a tx.
func (w *Wallet) LabelTransaction(hash chainhash.Hash, label string, overwrite bool) error {
	ctx := context.Background()
	txInfo, err := w.store.GetTx(ctx, db.GetTxQuery{
		WalletID: w.ID(),
		TxHash:   hash,
	})
	if err != nil {
		return ErrUnknownTransaction
	}

	// Return an error if a label already exists and we're not overwriting.
	if txInfo.Label != "" && !overwrite {
		return ErrTxLabelExists
	}

	// Set the label and return.
	return w.store.UpdateTx(ctx, db.UpdateTxParams{
		WalletID: w.ID(),
		TxHash:   hash,
		Data: db.TxUpdateData{
			Label: label,
		},
	})
}
