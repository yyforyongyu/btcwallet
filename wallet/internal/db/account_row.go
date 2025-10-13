// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import "github.com/btcsuite/btcwallet/waddrmgr"

// AccountType represents a type of address stored in the database.
type AccountType uint8

// DbDefaultAccountRow houses additional information stored about a default
// BIP0044-like account in the database.
type DbDefaultAccountRow struct {
	PubKeyEncrypted   []byte
	PrivKeyEncrypted  []byte
	NextExternalIndex uint32
	NextInternalIndex uint32
	Name              string
}

// DbWatchOnlyAccountRow houses additional information stored about a watch-only
// account in the databse.
type DbWatchOnlyAccountRow struct {
	PubKeyEncrypted      []byte
	MasterKeyFingerprint uint32
	NextExternalIndex    uint32
	NextInternalIndex    uint32
	Name                 string
	AddrSchema           *waddrmgr.ScopeAddrSchema
}
