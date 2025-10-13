// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"bytes"
	"encoding/binary"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/walletdb"
)

const (
	// TxLabelLimit is the length limit we impose on transaction labels.
	TxLabelLimit = 500
)

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
