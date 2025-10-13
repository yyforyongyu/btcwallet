// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// scopeToBytes transforms a manager's scope into the form that will be used to
// retrieve the bucket that all information for a particular scope is stored
// under
func scopeToBytes(scope *waddrmgr.KeyScope) [8]byte {
	var scopeBytes [8]byte
	binary.LittleEndian.PutUint32(scopeBytes[:], scope.Purpose)
	binary.LittleEndian.PutUint32(scopeBytes[4:], scope.Coin)

	return scopeBytes
}

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

	// mainBucketName is the name of the bucket that stores the encrypted
	// crypto keys that encrypt all other generated keys, the watch only
	// flag, the master private key (encrypted), the master HD private key
	// (encrypted), and also versioning information.
	mainBucketName = []byte("main")

	// Crypto related key names (main bucket).
	masterPrivKeyName   = []byte("mpriv")
	masterPubKeyName    = []byte("mpub")
	cryptoPrivKeyName   = []byte("cpriv")
	cryptoPubKeyName    = []byte("cpub")
	cryptoScriptKeyName = []byte("cscript")
	masterHDPrivName    = []byte("mhdpriv")
	masterHDPubName     = []byte("mhdpub")

	// scopeBucketName is the name of the top-level bucket within the
	// hierarchy.
	scopeBucketName = []byte("scope")

	// metaBucketName is used to store meta-data about the address manager.
	metaBucketName = []byte("meta")

	// lastAccountName is used to store the metadata - last account
	// in the manager.
	lastAccountName = []byte("lastaccount")

	// acctBucketName is the bucket directly below the scope bucket in the
	// hierarchy.
	acctBucketName = []byte("acct")
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

// PutSyncedTo stores the wallet's current sync state in the database.
func PutSyncedTo(ns walletdb.ReadWriteBucket, bs *waddrmgr.BlockStamp) error {
	syncBucket := ns.NestedReadWriteBucket(syncBucketName)
	if syncBucket == nil {
		return errNoSyncBucket
	}

	// Store synced to block.
	serializedBlock := serializeBlockStamp(bs)
	err := syncBucket.Put([]byte("syncedto"), serializedBlock)
	if err != nil {
		return newError(ErrDatabase, "failed to store synced to block", err)
	}

	return nil
}

// FetchMasterHDKeys attempts to fetch both the master HD private and public
// keys from the database. If this is a watch only wallet, then it's possible
// that the master private key isn't stored.
func FetchMasterHDKeys(ns walletdb.ReadBucket) ([]byte, []byte) {
	bucket := ns.NestedReadBucket(mainBucketName)

	var masterHDPrivEnc, masterHDPubEnc []byte

	// First, we'll try to fetch the master private key. If this database
	// is watch only, or the master has been neutered, then this won't be
	// found on disk.
	key := bucket.Get(masterHDPrivName)
	if key != nil {
		masterHDPrivEnc = make([]byte, len(key))
		copy(masterHDPrivEnc, key)
	}

	key = bucket.Get(masterHDPubName)
	if key != nil {
		masterHDPubEnc = make([]byte, len(key))
		copy(masterHDPubEnc, key)
	}

	return masterHDPrivEnc, masterHDPubEnc
}

// PutCryptoKeys stores the encrypted crypto keys which are in turn used to
// protect the extended and imported keys.  Either parameter can be nil in
// which case no value is written for the parameter.
func PutCryptoKeys(ns walletdb.ReadWriteBucket, pubKeyEncrypted, privKeyEncrypted,
	scriptKeyEncrypted []byte) error {

	bucket := ns.NestedReadWriteBucket(mainBucketName)

	if pubKeyEncrypted != nil {
		err := bucket.Put(cryptoPubKeyName, pubKeyEncrypted)
		if err != nil {
			return newError(ErrDatabase, "failed to store encrypted crypto public key", err)
		}
	}

	if privKeyEncrypted != nil {
		err := bucket.Put(cryptoPrivKeyName, privKeyEncrypted)
		if err != nil {
			return newError(ErrDatabase, "failed to store encrypted crypto private key", err)
		}
	}

	if scriptKeyEncrypted != nil {
		err := bucket.Put(cryptoScriptKeyName, scriptKeyEncrypted)
		if err != nil {
			return newError(ErrDatabase, "failed to store encrypted crypto script key", err)
		}
	}

	return nil
}

// FetchAccountInfo loads information about the passed account from the
// database.
func FetchAccountInfo(ns walletdb.ReadBucket, scope *waddrmgr.KeyScope,
	account uint32) (interface{}, error) {

	scopedBucket, err := fetchReadScopeBucket(ns, scope)
	if err != nil {
		return nil, err
	}

	acctBucket := scopedBucket.NestedReadBucket(acctBucketName)

	accountID := uint32ToBytes(account)
	serializedRow := acctBucket.Get(accountID)
	if serializedRow == nil {
		return nil, newError(ErrDatabase, fmt.Sprintf("account %d not found", account), nil)
	}

	row, err := deserializeAccountRow(accountID, serializedRow)
	if err != nil {
		return nil, err
	}

	switch row.acctType {
	case accountDefault:
		return deserializeDefaultAccountRow(accountID, row)
	case 1: // accountWatchOnly
		return deserializeWatchOnlyAccountRow(accountID, row)
	}

	return nil, newError(ErrDatabase, fmt.Sprintf("unsupported account type '%d'", row.acctType), nil)
}

// deserializeAccountRow deserializes the passed serialized account information.
// This is used as a common base for the various account types to deserialize
// the common parts.
func deserializeAccountRow(accountID []byte, serializedAccount []byte) (*dbAccountRow, error) {
	// The serialized account format is:
	//   <acctType><rdlen><rawdata>
	//
	// 1 byte acctType + 4 bytes raw data length + raw data

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	if len(serializedAccount) < 5 {
		return nil, newError(ErrDatabase, fmt.Sprintf("malformed serialized account for key %x", accountID), nil)
	}

	row := dbAccountRow{}
	row.acctType = AccountType(serializedAccount[0])
	rdlen := binary.LittleEndian.Uint32(serializedAccount[1:5])
	row.rawData = make([]byte, rdlen)
	copy(row.rawData, serializedAccount[5:5+rdlen])

	return &row, nil
}

// deserializeDefaultAccountRow deserializes the raw data from the passed

// account row as a BIP0044-like account.

func deserializeDefaultAccountRow(accountID []byte, row *dbAccountRow) (*DbDefaultAccountRow, error) {

	// The serialized BIP0044 account raw data format is:

	//   <encpubkeylen><encpubkey><encprivkeylen><encprivkey><nextextidx>

	//   <nextintidx><namelen><name>

	//

	// 4 bytes encrypted pubkey len + encrypted pubkey + 4 bytes encrypted

	// privkey len + encrypted privkey + 4 bytes next external index +

	// 4 bytes next internal index + 4 bytes name len + name



	// Given the above, the length of the entry must be at a minimum

	// the constant value sizes.

	if len(row.rawData) < 20 {

		return nil, newError(ErrDatabase, fmt.Sprintf("malformed serialized bip0044 account for key %x", accountID), nil)

	}



	retRow := DbDefaultAccountRow{}



	pubLen := binary.LittleEndian.Uint32(row.rawData[0:4])

	retRow.PubKeyEncrypted = make([]byte, pubLen)

	copy(retRow.PubKeyEncrypted, row.rawData[4:4+pubLen])

	offset := 4 + pubLen

	privLen := binary.LittleEndian.Uint32(row.rawData[offset : offset+4])

	offset += 4

	retRow.PrivKeyEncrypted = make([]byte, privLen)

	copy(retRow.PrivKeyEncrypted, row.rawData[offset:offset+privLen])

	offset += privLen

	retRow.NextExternalIndex = binary.LittleEndian.Uint32(row.rawData[offset : offset+4])

	offset += 4

	retRow.NextInternalIndex = binary.LittleEndian.Uint32(row.rawData[offset : offset+4])

	offset += 4

	nameLen := binary.LittleEndian.Uint32(row.rawData[offset : offset+4])

	offset += 4

	retRow.Name = string(row.rawData[offset : offset+nameLen])



	return &retRow, nil

}



// deserializeWatchOnlyAccountRow deserializes the raw data from the passed

// account row as a watch-only account.

func deserializeWatchOnlyAccountRow(accountID []byte,

	row *dbAccountRow) (*DbWatchOnlyAccountRow, error) {



	// The serialized BIP0044 watch-only account raw data format is:

	//   <encpubkeylen><encpubkey><masterkeyfingerprint><nextextidx>

	//   <nextintidx><namelen><name>

	//

	// 4 bytes encrypted pubkey len + encrypted pubkey + 4 bytes master key

	// fingerprint + 4 bytes next external index + 4 bytes next internal

	// index + 4 bytes name len + name + 1 byte addr schema exists + 2 bytes

	// addr schema (if exists)



	// Given the above, the length of the entry must be at a minimum

	// the constant value sizes.

	if len(row.rawData) < 21 {

		return nil, newError(ErrDatabase, fmt.Sprintf("malformed serialized watch-only account for key %x", accountID), nil)

	}



	retRow := DbWatchOnlyAccountRow{}

	r := bytes.NewReader(row.rawData)



	var pubLen uint32

	err := binary.Read(r, binary.LittleEndian, &pubLen)

	if err != nil {

		return nil, err

	}

	retRow.PubKeyEncrypted = make([]byte, pubLen)

	err = binary.Read(r, binary.LittleEndian, &retRow.PubKeyEncrypted)

	if err != nil {

		return nil, err

	}



	err = binary.Read(r, binary.LittleEndian, &retRow.MasterKeyFingerprint)

	if err != nil {

		return nil, err

	}



	err = binary.Read(r, binary.LittleEndian, &retRow.NextExternalIndex)

	if err != nil {

		return nil, err

	}

	err = binary.Read(r, binary.LittleEndian, &retRow.NextInternalIndex)

	if err != nil {

		return nil, err

	}



	var nameLen uint32

	err = binary.Read(r, binary.LittleEndian, &nameLen)

	if err != nil {

		return nil, err

	}

	name := make([]byte, nameLen)

	err = binary.Read(r, binary.LittleEndian, &name)

	if err != nil {

		return nil, err

	}

	retRow.Name = string(name)



	var addrSchemaExists bool

	err = binary.Read(r, binary.LittleEndian, &addrSchemaExists)

	if err != nil {

		return nil, err

	}

	if addrSchemaExists {

		var addrSchemaBytes [2]byte

		err = binary.Read(r, binary.LittleEndian, &addrSchemaBytes)

		if err != nil {

			return nil, err

		}

				addrSchema := ScopeSchemaFromBytes(addrSchemaBytes[:])

				retRow.AddrSchema = &addrSchema

			}



	return &retRow, nil

}


func fetchReadScopeBucket(ns walletdb.ReadBucket, scope *waddrmgr.KeyScope) (walletdb.ReadBucket, error) {
	rootScopeBucket := ns.NestedReadBucket(scopeBucketName)

	scopeKey := scopeToBytes(scope)
	scopedBucket := rootScopeBucket.NestedReadBucket(scopeKey[:])
	if scopedBucket == nil {
		return nil, newError(ErrDatabase, fmt.Sprintf("unable to find scope %v", scope), nil)
	}

	return scopedBucket, nil
}

// uint32ToBytes converts a 32 bit unsigned integer into a 4-byte slice in
// little-endian order: 1 -> [1 0 0 0].
func uint32ToBytes(number uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, number)
	return buf
}

const (
	// accountDefault is the current "default" account type within the
	// database. This is an account that re-uses the key derivation schema
	// of BIP0044-like accounts.
	accountDefault AccountType = 0 // not iota as they need to be stable
)

// dbAccountRow houses information stored about an account in the database.
type dbAccountRow struct {
	acctType AccountType
	rawData  []byte // Varies based on account type field.
}

// ScopeSchemaFromBytes decodes a new scope schema instance from the set of
// serialized bytes.
func ScopeSchemaFromBytes(schemaBytes []byte) waddrmgr.ScopeAddrSchema {
	return waddrmgr.ScopeAddrSchema{
		InternalAddrType: waddrmgr.AddressType(schemaBytes[0]),
		ExternalAddrType: waddrmgr.AddressType(schemaBytes[1]),
	}
}

// LastAccount returns the last account number for a given scope.
func LastAccount(ns walletdb.ReadBucket, scope *waddrmgr.KeyScope) (uint32, error) {
	scopedBucket, err := fetchReadScopeBucket(ns, scope)
	if err != nil {
		return 0, err
	}

	metaBucket := scopedBucket.NestedReadBucket(metaBucketName)
	val := metaBucket.Get(lastAccountName)
	if val == nil {
		return 0, newError(ErrDatabase, "last account not found", nil)
	}
	if len(val) != 4 {
		return 0, newError(ErrDatabase, fmt.Sprintf("malformed metadata '%s' stored in database", lastAccountName), nil)
	}

	account := binary.LittleEndian.Uint32(val[0:4])
	return account, nil
}

// PutMasterKeyParams stores the master key parameters needed to derive them to
// the database.  Either parameter can be nil in which case no value is
// written for the parameter.
func PutMasterKeyParams(ns walletdb.ReadWriteBucket, pubParams, privParams []byte) error {
	bucket := ns.NestedReadWriteBucket(mainBucketName)

	if privParams != nil {
		err := bucket.Put(masterPrivKeyName, privParams)
		if err != nil {
			return newError(ErrDatabase, "failed to store master private key parameters", err)
		}
	}

	if pubParams != nil {
		err := bucket.Put(masterPubKeyName, pubParams)
		if err != nil {
			return newError(ErrDatabase, "failed to store master public key parameters", err)
		}
	}

	return nil
}
