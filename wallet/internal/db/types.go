// Copyright (c) 2015-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// CreditRecord contains metadata regarding a transaction credit for a known
// transaction.  Further details may be looked up by indexing a wire.MsgTx.TxOut
// with the Index field.
type CreditRecord struct {
	Amount btcutil.Amount
	Index  uint32
	Spent  bool
	Change bool
}

// DebitRecord contains metadata regarding a transaction debit for a known
// transaction.  Further details may be looked up by indexing a wire.MsgTx.TxIn
// with the Index field.
type DebitRecord struct {
	Amount btcutil.Amount
	Index  uint32
}

// TxDetails is intended to provide callers with access to rich details
// regarding a relevant transaction and which inputs and outputs are credit or
// debits.
type TxDetails struct {
	wtxmgr.TxRecord
	Block   wtxmgr.BlockMeta
	Credits []CreditRecord
	Debits  []DebitRecord
	Label   string
}

// BlockRecord is an in-memory representation of the block record saved in the
// database.
type BlockRecord struct {
	wtxmgr.Block
	Time         time.Time
	Transactions []chainhash.Hash
}
