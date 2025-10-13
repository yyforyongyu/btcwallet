// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"encoding/binary"
	"time"

	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// syncBucketName is the name of the bucket that stores the current
	// sync state of the root manager.
	syncBucketName = []byte("sync")

	// birthdayName is the database key for the wallet's birthday.
	birthdayName = []byte("birthday")
)

// PutBirthday stores the wallet's birthday in the database.
func PutBirthday(ns walletdb.ReadWriteBucket, birthday time.Time) error {
	syncBucket := ns.NestedReadWriteBucket(syncBucketName)
	if syncBucket == nil {
		return errNoSyncBucket
	}

	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(birthday.Unix()))

	err := syncBucket.Put(birthdayName, buf[:])
	if err != nil {
		return newError(ErrDatabase, "failed to store birthday", err)
	}

	return nil
}
