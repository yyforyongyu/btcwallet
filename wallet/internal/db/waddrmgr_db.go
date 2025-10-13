// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"encoding/binary"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// syncBucketName is the name of the bucket that stores the current
	// sync state of the root manager.
	syncBucketName = []byte("sync")

	// birthdayName is the database key for the wallet's birthday.
	birthdayName = []byte("birthday")

	// birthdayBlockName is the database key for the wallet's birthday block.
	birthdayBlockName = []byte("birthdayblock")

	// birthdayBlockVerifiedName is the database key for whether the wallet's
	// birthday block has been verified.
	birthdayBlockVerifiedName = []byte("birthdayblockverified")
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

// PutBirthdayBlock stores the wallet's birthday block in the database.
func PutBirthdayBlock(ns walletdb.ReadWriteBucket, block waddrmgr.BlockStamp, verified bool) error {
	syncBucket := ns.NestedReadWriteBucket(syncBucketName)
	if syncBucket == nil {
		return errNoSyncBucket
	}

	// Store birthday block.
	serializedBlock := serializeBlockStamp(&block)
	err := syncBucket.Put(birthdayBlockName, serializedBlock)
	if err != nil {
		return newError(ErrDatabase, "failed to store birthday block", err)
	}

	// Store birthday block verified flag.
	var verifiedBytes [1]byte
	if verified {
		verifiedBytes[0] = 1
	}
	err = syncBucket.Put(birthdayBlockVerifiedName, verifiedBytes[:])
	if err != nil {
		return newError(ErrDatabase, "failed to store birthday block verified flag", err)
	}

	return nil
}

// serializeBlockStamp returns the serialization of the passed block stamp.
func serializeBlockStamp(block *waddrmgr.BlockStamp) []byte {
	// The serialized block stamp format is:
	//   <height><hash><timestamp>
	//
	// 4 bytes height + 32 bytes hash + 8 bytes timestamp
	serialized := make([]byte, 44)
	binary.LittleEndian.PutUint32(serialized[0:4], uint32(block.Height))
	copy(serialized[4:36], block.Hash[:])
	binary.LittleEndian.PutUint64(serialized[36:44], uint64(block.Timestamp.Unix()))
	return serialized
}
