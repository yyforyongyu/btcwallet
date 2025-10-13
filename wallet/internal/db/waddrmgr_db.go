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

// BirthdayBlock returns the birthday block of the wallet.
func BirthdayBlock(ns walletdb.ReadBucket) (waddrmgr.BlockStamp, bool, error) {
	syncBucket := ns.NestedReadBucket(syncBucketName)
	if syncBucket == nil {
		return waddrmgr.BlockStamp{}, false, errNoSyncBucket
	}

	// Fetch birthday block.
	serializedBlock := syncBucket.Get(birthdayBlockName)
	if serializedBlock == nil {
		return waddrmgr.BlockStamp{}, false, nil
	}
	block, err := deserializeBlockStamp(serializedBlock)
	if err != nil {
		return waddrmgr.BlockStamp{}, false, err
	}

	// Fetch birthday block verified flag.
	verifiedBytes := syncBucket.Get(birthdayBlockVerifiedName)
	if verifiedBytes == nil {
		return waddrmgr.BlockStamp{}, false, nil
	}

	return *block, verifiedBytes[0] == 1, nil
}

// deserializeBlockStamp deserializes the passed serialized block stamp.
func deserializeBlockStamp(serializedBlock []byte) (*waddrmgr.BlockStamp, error) {
	// The serialized block stamp format is:
	//   <height><hash><timestamp>
	//
	// 4 bytes height + 32 bytes hash + 8 bytes timestamp
	if len(serializedBlock) != 44 {
		return nil, newError(ErrDatabase, "malformed serialized block stamp", nil)
	}

	block := waddrmgr.BlockStamp{
		Height: int32(binary.LittleEndian.Uint32(serializedBlock[0:4])),
		Timestamp: time.Unix(int64(binary.LittleEndian.Uint64(serializedBlock[36:44])), 0),
	}
	copy(block.Hash[:], serializedBlock[4:36])
	return &block, nil
}
