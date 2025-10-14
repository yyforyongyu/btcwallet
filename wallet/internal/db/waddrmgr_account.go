// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// lastAccountName is used to store the metadata - last account
	// in the manager.
	lastAccountName = []byte("lastaccount")

	// acctIDIdxBucketName is used to create an index mapping an account id
	// to the corresponding account name string.
	acctIDIdxBucketName = []byte("acctididx")

	// acctNameIdxBucketName is used to create an index mapping an account
	// name string to the corresponding account id.
	acctNameIdxBucketName = []byte("acctnameidx")

	// acctBucketName is the bucket directly below the scope bucket in the
	// hierarchy.
	acctBucketName = []byte("acct")
)

// DeleteAccountIDIndex deletes the given key from the account id index of the database.
func DeleteAccountIDIndex(ns walletdb.ReadWriteBucket, scope *waddrmgr.KeyScope,
	account uint32) error {

	scopedBucket, err := fetchWriteScopeBucket(ns, scope)
	if err != nil {
		return err
	}

	bucket := scopedBucket.NestedReadWriteBucket(acctIDIdxBucketName)

	// Delete the account id key
	err = bucket.Delete(uint32ToBytes(account))
	if err != nil {
		return newError(ErrDatabase, fmt.Sprintf("failed to delete account id index key %d", account), err)
	}
	return nil
}

// DeleteAccountNameIndex deletes the given key from the account name index of the database.
func DeleteAccountNameIndex(ns walletdb.ReadWriteBucket, scope *waddrmgr.KeyScope,
	name string) error {

	scopedBucket, err := fetchWriteScopeBucket(ns, scope)
	if err != nil {
		return err
	}

	bucket := scopedBucket.NestedReadWriteBucket(acctNameIdxBucketName)

	// Delete the account name key
	err = bucket.Delete(stringToBytes(name))
	if err != nil {
		return newError(ErrDatabase, fmt.Sprintf("failed to delete account name index key %s", name), err)
	}
	return nil
}

func fetchWriteScopeBucket(ns walletdb.ReadWriteBucket,
	scope *waddrmgr.KeyScope) (walletdb.ReadWriteBucket, error) {

	rootScopeBucket := ns.NestedReadWriteBucket(scopeBucketName)

	scopeKey := scopeToBytes(scope)
	scopedBucket := rootScopeBucket.NestedReadWriteBucket(scopeKey[:])
	if scopedBucket == nil {
		return nil, newError(ErrDatabase, fmt.Sprintf("unable to find scope %v", scope), nil)
	}

	return scopedBucket, nil
}

// stringToBytes converts a string into a variable length byte slice in
// little-endian order: "abc" -> [3 0 0 0 61 62 63]
func stringToBytes(s string) []byte {
	// The serialized format is:
	//   <size><string>
	//
	// 4 bytes string size + string
	size := len(s)
	buf := make([]byte, 4+size)
	copy(buf[0:4], uint32ToBytes(uint32(size)))
	copy(buf[4:4+size], s)
	return buf
}

// dbAccountRow houses information stored about an account in the database.
type dbAccountRow struct {
	acctType AccountType
	rawData  []byte // Varies based on account type field.
}

// scopeToBytes transforms a manager's scope into the form that will be used to
// retrieve the bucket that all information for a particular scope is stored
// under
func scopeToBytes(scope *waddrmgr.KeyScope) [8]byte {
	var scopeBytes [8]byte
	binary.LittleEndian.PutUint32(scopeBytes[:], scope.Purpose)
	binary.LittleEndian.PutUint32(scopeBytes[4:], scope.Coin)

	return scopeBytes
}

// putAccountInfo stores the provided account information to the database.
func putAccountInfo(ns walletdb.ReadWriteBucket, scope *waddrmgr.KeyScope,
	account uint32, row *dbAccountRow, name string) error {

	if err := putAccountRow(ns, scope, account, row); err != nil {
		return err
	}

	// Update account id index.
	if err := putAccountIDIndex(ns, scope, account, name); err != nil {
		return err
	}

	// Update account name index.
	return putAccountNameIndex(ns, scope, account, name)
}

// ScopeSchemaFromBytes decodes a new scope schema instance from the set of
// serialized bytes.
func ScopeSchemaFromBytes(schemaBytes []byte) waddrmgr.ScopeAddrSchema {
	return waddrmgr.ScopeAddrSchema{
		InternalAddrType: waddrmgr.AddressType(schemaBytes[0]),
		ExternalAddrType: waddrmgr.AddressType(schemaBytes[1]),
	}
}

const (
	// accountDefault is the current "default" account type within the
	// database. This is an account that re-uses the key derivation schema
	// of BIP0044-like accounts.
	accountDefault AccountType = 0 // not iota as they need to be stable

	// accountWatchOnly is the account type used for storing watch-only
	// accounts within the database.
	accountWatchOnly AccountType = 1
)

// putLastAccount stores the provided metadata - last account - to the
// database.
func putLastAccount(ns walletdb.ReadWriteBucket, scope *waddrmgr.KeyScope,
	account uint32) error {

	scopedBucket, err := fetchWriteScopeBucket(ns, scope)
	if err != nil {
		return err
	}

	bucket := scopedBucket.NestedReadWriteBucket(metaBucketName)

	err = bucket.Put(lastAccountName, uint32ToBytes(account))
	if err != nil {
		return newError(ErrDatabase, fmt.Sprintf("failed to update metadata '%s'", lastAccountName), err)
	}
	return nil
}

// fetchAccountInfo loads information about the passed account from the
// database.
func fetchAccountInfo(ns walletdb.ReadBucket, scope *waddrmgr.KeyScope,
	account uint32) (interface{}, error) {

	scopedBucket, err := fetchReadScopeBucket(ns, scope)
	if err != nil {
		return nil, err
	}

	acctBucket := scopedBucket.NestedReadBucket(acctBucketName)

	accountID := uint32ToBytes(account)
	serializedRow := acctBucket.Get(accountID)
	if serializedRow == nil {
		return nil, newError(ErrAccountNotFound, fmt.Sprintf("account %d not found", account), nil)
	}

	row, err := deserializeAccountRow(accountID, serializedRow)
	if err != nil {
		return nil, err
	}

	switch row.acctType {
	case accountDefault:
		return deserializeDefaultAccountRow(accountID, row)
	case accountWatchOnly:
		return deserializeWatchOnlyAccountRow(accountID, row)
	}

	return nil, newError(ErrDatabase, fmt.Sprintf("unsupported account type '%d'", row.acctType), nil)
}

// FetchAccountByName retrieves the account number given an account name from
// the database.
func FetchAccountByName(ns walletdb.ReadBucket, scope *waddrmgr.KeyScope,
	name string) (uint32, error) {

	scopedBucket, err := fetchReadScopeBucket(ns, scope)
	if err != nil {
		return 0, err
	}

	idxBucket := scopedBucket.NestedReadBucket(acctNameIdxBucketName)

	val := idxBucket.Get(stringToBytes(name))
	if val == nil {
		return 0, newError(ErrAccountNotFound, fmt.Sprintf("account name '%s' not found", name), nil)
	}

	return binary.LittleEndian.Uint32(val), nil
}

// PutDefaultAccountInfo stores the provided default account information to the
// database.
func PutDefaultAccountInfo(ns walletdb.ReadWriteBucket, scope *waddrmgr.KeyScope,
	account uint32, encryptedPubKey, encryptedPrivKey []byte,
	nextExternalIndex, nextInternalIndex uint32, name string) error {
	rawData := serializeDefaultAccountRow(
		encryptedPubKey, encryptedPrivKey, nextExternalIndex,
		nextInternalIndex, name,
	)

	row := dbAccountRow{
		acctType: accountDefault,
		rawData:  rawData,
	}
	return putAccountInfo(ns, scope, account, &row, name)
}

// putAccountRow stores the provided account information to the database.  This
// is used a common base for storing the various account types.
func putAccountRow(ns walletdb.ReadWriteBucket, scope *waddrmgr.KeyScope,
	account uint32, row *dbAccountRow) error {

	scopedBucket, err := fetchWriteScopeBucket(ns, scope)
	if err != nil {
		return err
	}

	bucket := scopedBucket.NestedReadWriteBucket(acctBucketName)

	// Write the serialized value keyed by the account number.
	err = bucket.Put(uint32ToBytes(account), serializeAccountRow(row))
	if err != nil {
		return newError(ErrDatabase, fmt.Sprintf("failed to store account %d", account), err)
	}
	return nil
}

// uint32ToBytes converts a 32 bit unsigned integer into a 4-byte slice in
// little-endian order: 1 -> [1 0 0 0].
func uint32ToBytes(number uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, number)
	return buf
}

// serializeAccountRow returns the serialization of the passed account row.
func serializeAccountRow(row *dbAccountRow) []byte {
	// The serialized account format is:
	//   <acctType><rdlen><rawdata>
	//
	// 1 byte acctType + 4 bytes raw data length + raw data
	rdlen := len(row.rawData)
	buf := make([]byte, 5+rdlen)
	buf[0] = byte(row.acctType)
	binary.LittleEndian.PutUint32(buf[1:5], uint32(rdlen))
	copy(buf[5:5+rdlen], row.rawData)
	return buf
}

// putAccountIDIndex stores the given key to the account id index of the database.
func putAccountIDIndex(ns walletdb.ReadWriteBucket, scope *waddrmgr.KeyScope,
	account uint32, name string) error {

	scopedBucket, err := fetchWriteScopeBucket(ns, scope)
	if err != nil {
		return err
	}

	bucket := scopedBucket.NestedReadWriteBucket(acctIDIdxBucketName)

	// Write the account number keyed by the account id.
	err = bucket.Put(uint32ToBytes(account), stringToBytes(name))
	if err != nil {
		return newError(ErrDatabase, fmt.Sprintf("failed to store account id index key %s", name), err)
	}
	return nil
}

// putAccountNameIndex stores the given key to the account name index of the
// database.
func putAccountNameIndex(ns walletdb.ReadWriteBucket, scope *waddrmgr.KeyScope,
	account uint32, name string) error {

	scopedBucket, err := fetchWriteScopeBucket(ns, scope)
	if err != nil {
		return err
	}

	bucket := scopedBucket.NestedReadWriteBucket(acctNameIdxBucketName)

	// Write the account number keyed by the account name.
	err = bucket.Put(stringToBytes(name), uint32ToBytes(account))
	if err != nil {
		return newError(ErrDatabase, fmt.Sprintf("failed to store account name index key %s", name), err)
	}
	return nil
}

// PutWatchOnlyAccountInfo stores the provided watch-only account information to
// the database.
func PutWatchOnlyAccountInfo(ns walletdb.ReadWriteBucket, scope *waddrmgr.KeyScope,
	account uint32, encryptedPubKey []byte, masterKeyFingerprint,
	nextExternalIndex, nextInternalIndex uint32, name string,
	addrSchema *waddrmgr.ScopeAddrSchema) error {

	rawData, err := serializeWatchOnlyAccountRow(
		encryptedPubKey, masterKeyFingerprint, nextExternalIndex,
		nextInternalIndex, name, addrSchema,
	)
	if err != nil {
		return err
	}

	acctRow := dbAccountRow{
		acctType: accountWatchOnly,
		rawData:  rawData,
	}
	return putAccountInfo(ns, scope, account, &acctRow, name)
}

// serializeWatchOnlyAccountRow returns the serialization of the raw data field
// for a watch-only account.
func serializeWatchOnlyAccountRow(encryptedPubKey []byte, masterKeyFingerprint,
	nextExternalIndex, nextInternalIndex uint32, name string,
	addrSchema *waddrmgr.ScopeAddrSchema) ([]byte, error) {

	// The serialized BIP0044 account raw data format is:
	//   <encpubkeylen><encpubkey><masterkeyfingerprint><nextextidx>
	//   <nextintidx><namelen><name>
	//
	// 4 bytes encrypted pubkey len + encrypted pubkey + 4 bytes master key
	// fingerprint + 4 bytes next external index + 4 bytes next internal
	// index + 4 bytes name len + name + 1 byte addr schema exists + 2 bytes
	// addr schema (if exists)
	pubLen := uint32(len(encryptedPubKey))
	nameLen := uint32(len(name))

	addrSchemaExists := addrSchema != nil
	var addrSchemaBytes []byte
	if addrSchemaExists {
		addrSchemaBytes = scopeSchemaToBytes(addrSchema)
	}

	bufLen := 21 + pubLen + nameLen + uint32(len(addrSchemaBytes))
	buf := bytes.NewBuffer(make([]byte, 0, bufLen))

	err := binary.Write(buf, binary.LittleEndian, pubLen)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, encryptedPubKey)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, masterKeyFingerprint)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, nextExternalIndex)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, nextInternalIndex)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, nameLen)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, []byte(name))
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, addrSchemaExists)
	if err != nil {
		return nil, err
	}
	if addrSchemaExists {
		err = binary.Write(buf, binary.LittleEndian, addrSchemaBytes)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// scopeSchemaToBytes encodes the passed scope schema as a set of bytes
// suitable for storage within the database.
func scopeSchemaToBytes(schema *waddrmgr.ScopeAddrSchema) []byte {
	var schemaBytes [2]byte
	schemaBytes[0] = byte(schema.InternalAddrType)
	schemaBytes[1] = byte(schema.ExternalAddrType)

	return schemaBytes[:]
}

// serializeDefaultAccountRow returns the serialization of the raw data field
// for a BIP0044-like account.
func serializeDefaultAccountRow(encryptedPubKey, encryptedPrivKey []byte,
	nextExternalIndex, nextInternalIndex uint32, name string) []byte {

	// The serialized BIP0044 account raw data format is:
	//   <encpubkeylen><encpubkey><encprivkeylen><encprivkey><nextextidx>
	//   <nextintidx><namelen><name>
	//
	// 4 bytes encrypted pubkey len + encrypted pubkey + 4 bytes encrypted
	// privkey len + encrypted privkey + 4 bytes next external index +
	// 4 bytes next internal index + 4 bytes name len + name
	pubLen := uint32(len(encryptedPubKey))
	privLen := uint32(len(encryptedPrivKey))
	nameLen := uint32(len(name))
	rawData := make([]byte, 20+pubLen+privLen+nameLen)
	binary.LittleEndian.PutUint32(rawData[0:4], pubLen)
	copy(rawData[4:4+pubLen], encryptedPubKey)
	offset := 4 + pubLen
	binary.LittleEndian.PutUint32(rawData[offset:offset+4], privLen)
	offset += 4
	copy(rawData[offset:offset+privLen], encryptedPrivKey)
	offset += privLen
	binary.LittleEndian.PutUint32(rawData[offset:offset+4], nextExternalIndex)
	offset += 4
	binary.LittleEndian.PutUint32(rawData[offset:offset+4], nextInternalIndex)
	offset += 4
	binary.LittleEndian.PutUint32(rawData[offset:offset+4], nameLen)
	offset += 4
	copy(rawData[offset:offset+nameLen], name)
	return rawData
}