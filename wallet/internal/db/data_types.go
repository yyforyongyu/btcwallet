// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"errors"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

var (
	// ErrNotFound is returned when a requested item is not found in the
	// database.
	ErrNotFound = errors.New("item not found")
)

// ============================================================================
// Data Types & Method Parameters
// ============================================================================

// KeyScope represents the BIP-44 key scope.
type KeyScope struct {
	Purpose uint32
	Coin    uint32
}

// AddressType is the type of a managed address.
type AddressType uint8

const (
	// PubKeyHash represents a p2pkh address.
	PubKeyHash AddressType = iota

	// ScriptHash represents a p2sh address.
	ScriptHash

	// WitnessPubKey represents a p2wkh address.
	WitnessPubKey

	// NestedWitnessPubKey represents a p2wkh output nested within a p2sh
	// address.
	NestedWitnessPubKey
)

// Tapscript represents a taproot script leaf.
type Tapscript struct {
	ControlBlock []byte
	Script       []byte
}

// --------------------
// WalletStore Types
// --------------------

// WalletInfo contains the static properties of a wallet.
type WalletInfo struct {
	ID          uint64
	Name        string
	IsImported  bool
	IsWatchOnly bool
	Birthday    time.Time
	SyncState   SyncState
}

// CreateWalletParams contains the parameters for the CreateWallet method.
type CreateWalletParams struct {
	Name              string
	PublicPassphrase  []byte
	PrivatePassphrase []byte
	HDSeed            []byte
	IsImported        bool
}

// UpdateSyncStateParams contains the parameters for the UpdateSyncState method.
type UpdateSyncStateParams struct {
	WalletID      uint64
	SyncState     SyncState
	BirthdayBlock *waddrmgr.BlockStamp
}

// GetHDSeedParams contains the parameters for the GetHDSeed method.
type GetHDSeedParams struct {
	WalletID          uint64
	PrivatePassphrase []byte
}

// SyncState represents the wallet's current synchronization state.
type SyncState struct {
	SyncedTo  chainhash.Hash
	Height    int32
	Timestamp time.Time
}

// --------------------
// AccountStore Types
// --------------------

// AccountInfo contains all information about a single account.
type AccountInfo struct {
	AccountNumber      uint32
	AccountName        string
	ExternalKeyCount   uint32
	InternalKeyCount   uint32
	ImportedKeyCount   uint32
	ConfirmedBalance   btcutil.Amount
	UnconfirmedBalance btcutil.Amount
	IsWatchOnly        bool
	AddrSchema         *waddrmgr.ScopeAddrSchema
}

// CreateAccountParams contains the parameters for the CreateAccount method.
type CreateAccountParams struct {
	WalletID uint64
	Scope    KeyScope
	Name     string
}

// ImportAccountParams contains the data required to import an account.
type ImportAccountParams struct {
	WalletID             uint64
	Name                 string
	AccountKey           *hdkeychain.ExtendedKey
	MasterKeyFingerprint uint32
	AddressType          *AddressType
}

// GetAccountQuery contains the parameters for the GetAccount method.
type GetAccountQuery struct {
	WalletID      uint64
	Scope         KeyScope
	Name          *string
	AccountNumber *uint32
}

// ListAccountsQuery holds the set of options for a ListAccounts query.
type ListAccountsQuery struct {
	WalletID uint64
	Scope    *KeyScope
	Name     *string
}

// UpdateAccountNameParams contains the parameters for the UpdateAccountName method.
type UpdateAccountNameParams struct {
	WalletID uint64
	Scope    KeyScope
	OldName  string
	NewName  string
}

// RenameAccountParams contains the parameters for the RenameAccount method.
type RenameAccountParams struct {
	WalletID      uint64
	Scope         KeyScope
	AccountNumber uint32
	NewName       string
}

// ImportAccountWithScopeParams contains the data required to import an account
// with a defined scope.
type ImportAccountWithScopeParams struct {
	Name                 string
	AccountKey           *hdkeychain.ExtendedKey
	MasterKeyFingerprint uint32
	Scope                KeyScope
	AddrSchema           waddrmgr.ScopeAddrSchema
}

// --------------------
// AddressStore Types
// --------------------

// AddressInfo represents a wallet-managed address.
type AddressInfo struct {
	Address        btcutil.Address
	Internal       bool
	Compressed     bool
	Used           bool
	AddrType       AddressType
	DerivationInfo DerivationInfo
	Script         []byte
	Account        uint32
}

// ImportAddressData encapsulates all the data needed to store a new, imported
// address or script.
type ImportAddressData struct {
	WalletID uint64
	Scope    KeyScope
	PubKey   *btcec.PublicKey
	Tapscript *Tapscript
	Script   []byte
	Rescan   bool
}

// CreateAddressParams contains the parameters for the CreateAddress method.
type CreateAddressParams struct {
	WalletID    uint64
	AccountName string
	Scope       KeyScope
	Change      bool
}

// GetUnusedAddressQuery contains the parameters for the GetUnusedAddress
// method.
type GetUnusedAddressQuery struct {
	WalletID    uint64
	AccountName string
	Scope       KeyScope
	Change      bool
}

// ImportPublicKeyParams contains the parameters for the ImportPublicKey method.
type ImportPublicKeyParams struct {
	WalletID uint64
	PubKey   *btcec.PublicKey
	Scope    KeyScope
}

// ImportTaprootScriptParams contains the parameters for the
// ImportTaprootScript method.
type ImportTaprootScriptParams struct {
	WalletID  uint64
	Tapscript Tapscript
}

// ImportPrivateKeyParams contains the parameters for the ImportPrivateKey
// method.
type ImportPrivateKeyParams struct {
	Scope  KeyScope
	WIF    *btcutil.WIF
	Rescan bool
	Bs     *waddrmgr.BlockStamp
}

// GetAddressQuery contains the parameters for the GetAddress method.
type GetAddressQuery struct {
	WalletID uint64
	Address  btcutil.Address
}

// ListAddressesQuery contains the parameters for the ListAddresses method.
type ListAddressesQuery struct {
	WalletID    uint64
	AccountName string
	Scope       KeyScope
}

// MarkAddressAsUsedParams contains the parameters for the MarkAddressAsUsed method.
type MarkAddressAsUsedParams struct {
	WalletID uint64
	Address  btcutil.Address
}

// DerivationInfo contains the BIP-32 derivation path information for a key.
type DerivationInfo struct {
	KeyScope             KeyScope
	MasterKeyFingerprint uint32
	Account              uint32
	Branch               uint32
	Index                uint32
}

// --------------------
// TxStore Types
// --------------------

// TxInfo represents the details of a transaction relevant to the wallet.
type TxInfo struct {
	Hash         chainhash.Hash
	SerializedTx []byte
	Received     time.Time
	Block        BlockMeta
	Credits      []Credit
	Debits       []Debit
	Label        string
}

// CreateTxParams contains the parameters for the CreateTx method.
type CreateTxParams struct {
	WalletID uint64
	Tx       *wire.MsgTx
	Label    string
	Credits  []CreditData
}

// CreditData contains the information needed to record a transaction credit.
type CreditData struct {
	Index   uint32
	Address btcutil.Address
}

// UpdateTxParams contains the parameters for the UpdateTx method.
type UpdateTxParams struct {
	WalletID uint64
	TxHash   chainhash.Hash
	Data     TxUpdateData
}

// GetTxQuery contains the parameters for the GetTx method.
type GetTxQuery struct {
	WalletID uint64
	TxHash   chainhash.Hash
}

// ListTxsQuery contains the parameters for the ListTxs method.
type ListTxsQuery struct {
	WalletID    uint64
	StartHeight int32
	EndHeight   int32
}

// DeleteTxParams contains the parameters for the DeleteTx method.
type DeleteTxParams struct {
	WalletID uint64
	Tx       *wire.MsgTx
}

// TxUpdateData contains the data required to update a transaction.
type TxUpdateData struct {
	BlockMeta BlockMeta
	Label     string
}

// BlockMeta contains metadata about the block that includes a transaction.
type BlockMeta struct {
	Hash   chainhash.Hash
	Height int32
	Time   time.Time
}

// Credit represents a transaction output that is controlled by the wallet.
type Credit struct {
	OutPoint wire.OutPoint
	Amount   btcutil.Amount
	PkScript []byte
}

// Debit represents a transaction input that spends a previous wallet output.
type Debit struct {
	TxIn   wire.TxIn
	Amount btcutil.Amount
}

// --------------------
// UTXOStore Types
// --------------------

// UtxoInfo represents an unspent transaction output.
type UtxoInfo struct {
	OutPoint     wire.OutPoint
	Amount       btcutil.Amount
	PkScript     []byte
	Received     time.Time
	FromCoinBase bool
	Height       int32
}

// CreateUtxoParams contains the parameters for the CreateUTXO method.
type CreateUtxoParams struct {
	WalletID uint64
	Utxo     UtxoInfo
}

// GetUtxoQuery contains the parameters for the GetUTXO method.
type GetUtxoQuery struct {
	WalletID uint64
	OutPoint wire.OutPoint
}

// DeleteUtxoParams contains the parameters for the DeleteUTXO method.
type DeleteUtxoParams struct {
	WalletID uint64
	OutPoint wire.OutPoint
}

// ListUtxosQuery holds the set of options for a ListUTXOs query.
type ListUtxosQuery struct {
	WalletID uint64
	Account  *uint32
	MinConfs int32
	MaxConfs int32
}

// LockUtxoParams contains the parameters for the LockUTXO method.
type LockUtxoParams struct {
	WalletID uint64
	ID       [32]byte
	OutPoint wire.OutPoint
	Duration time.Duration
}

// UnlockUtxoParams contains the parameters for the UnlockUTXO method.
type UnlockUtxoParams struct {
	WalletID uint64
	ID       [32]byte
	OutPoint wire.OutPoint
}

// LeasedUtxoInfo represents a UTXO that is currently locked.
type LeasedUtxoInfo struct {
	OutPoint   wire.OutPoint
	LockID     [32]byte
	Expiration time.Time
}