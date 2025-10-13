// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"github.com/btcsuite/btcwallet/walletdb"
)

// TODO(yy): The TxStore interface is a temporary solution to decouple the
// wallet from the wtxmgr. It is not a good example of a well-designed
// interface. It has the following issues:
//
//  1. Violation of the Interface Segregation Principle (ISP):
//     The current TxStore interface is a "fat" interface, containing over 15
//     methods that span a wide range of responsibilities, from simple balance
//     lookups to administrative tasks like database rollbacks. A component that
//     only needs to read transaction details is forced to depend on the entire
//     interface, including methods for writing data and performing
//     administrative actions. This creates an unnecessarily large dependency
//     surface.
//
//  2. Lack of Cohesion and CRUD-like Grouping:
//     The methods in TxStore are not grouped by the domain entity they operate
//     on. A more intuitive design would follow a classic Create, Read, Update,
//     Delete (CRUD) pattern for each major entity (transactions, UTXOs,
//     labels). The flat structure of the interface makes it harder to
//     understand the available operations for a specific entity. For example,
//     PutTxLabel, FetchTxLabel, and TxDetails are all at the same level, despite
//     operating on different aspects of a transaction.
//
//  3. Leaky Abstractions:
//     The interface methods currently require the caller (the wallet package)
//     to pass in walletdb.ReadWriteBucket or walletdb.ReadBucket handles. This
//     leaks the implementation detail that the store is built on walletdb. The
//     wallet should not need to know about the underlying database technology
//     or manage database transactions for the wtxmgr. This also violates the
//     "Pull Complexity Downwards" principle, as the TxStore should be
//     responsible for its own data access logic.
//
//  4. Missing context.Context Propagation:
//     None of the interface methods accept a context.Context. This is a
//     critical omission. Without a context, we cannot enforce timeouts,
//     propagate cancellation signals, or ensure the graceful shutdown of
//     long-running database queries.
//
// TxStore is an interface that describes a transaction store.
type TxStore interface {
	// a transaction that is already recorded.
	InsertTx(ns walletdb.ReadWriteBucket, rec *TxRecord, block *BlockMeta) error
}
