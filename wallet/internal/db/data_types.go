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

// KeyScope represents the BIP-44 key scope as defined in BIP-43. It is used
// to organize keys based on their purpose and coin type, providing a
// hierarchical structure for key derivation.
type KeyScope struct {
	// Purpose is the purpose number for the scope, as defined in BIP-43.
	Purpose uint32

	// Coin is the coin type number for the scope, as defined in BIP-44.
	Coin uint32
}

// AddressType specifies the type of a managed address. This is used to
// identify the script type of an address, such as P2PKH, P2SH, P2WKH, etc.
type AddressType uint8

const (
	// PubKeyHash represents a pay-to-pubkey-hash (P2PKH) address.
	PubKeyHash AddressType = iota

	// ScriptHash represents a pay-to-script-hash (P2SH) address.
	ScriptHash

	// WitnessPubKey represents a pay-to-witness-pubkey-hash (P2WKH) address.
	WitnessPubKey

	// NestedWitnessPubKey represents a P2WKH output nested within a P2SH
	// address.
	NestedWitnessPubKey
)

// Tapscript represents a Taproot script leaf, which includes the script itself
// and its corresponding control block. This is used for spending Taproot
// outputs.
type Tapscript struct {
	// ControlBlock is the control block for the Taproot script, which is
	// required to reveal the script path during spending.
	ControlBlock []byte

	// Script is the actual script code of the Taproot leaf.
	Script []byte
}

// --------------------
// WalletStore Types
// --------------------

// WalletInfo contains the static properties of a wallet. This struct provides a
// summary of the wallet's configuration and state.
type WalletInfo struct {
	// ID is the unique identifier for the wallet.
	ID uint64

	// Name is the human-readable name of the wallet.
	Name string

	// IsImported indicates whether the wallet was created from an existing
	// seed or was created as a new wallet.
	IsImported bool

	// IsWatchOnly indicates whether the wallet is in watch-only mode, meaning
	// it does not have private keys and cannot sign transactions.
	IsWatchOnly bool

	// Birthday is the timestamp of the wallet's creation, used as a starting
	// point for rescans.
	Birthday time.Time

	// BirthdayBlock is the block hash and height from which to start a rescan.
	BirthdayBlock waddrmgr.BlockStamp

	// SyncState represents the wallet's current synchronization state with
	// the blockchain.
	SyncState SyncState
}

// CreateWalletParams contains the parameters required to create a new wallet.
type CreateWalletParams struct {
	// Name is the name of the new wallet.
	Name string

	// PublicPassphrase is the passphrase used to encrypt public data.
	PublicPassphrase []byte

	// PrivatePassphrase is the passphrase used to encrypt private keys.
	PrivatePassphrase []byte

	// HDSeed is the Hierarchical Deterministic (HD) seed for the new wallet.
	HDSeed []byte

	// IsImported should be set to true if the wallet is being created from an
	// existing seed.
	IsImported bool
}

// UpdateWalletParams contains the parameters for updating a wallet's
// properties. Fields are pointers to allow for partial updates.
type UpdateWalletParams struct {
	// WalletID is the ID of the wallet to update.
	WalletID uint64

	// Birthday is the new birthday for the wallet.
	Birthday *time.Time

	// BirthdayBlock is the new birthday block for the wallet.
	BirthdayBlock *waddrmgr.BlockStamp

	// SyncState is the new synchronization state for the wallet.
	SyncState *SyncState
}

// SyncState represents the wallet's current synchronization state with the
// blockchain, indicating the last block that has been processed.
type SyncState struct {
	// SyncedTo is the hash of the last block the wallet is synced to.
	SyncedTo chainhash.Hash

	// Height is the height of the last block the wallet is synced to.
	Height int32

	// Timestamp is the timestamp of the last block the wallet is synced to.
	Timestamp time.Time
}

// --------------------
// AccountStore Types
// --------------------

// AccountInfo contains all information about a single account, including its
// properties and balances.
type AccountInfo struct {
	// AccountNumber is the unique identifier for the account.
	AccountNumber uint32

	// AccountName is the human-readable name of the account.
	AccountName string

	// ExternalKeyCount is the number of external keys that have been derived.
	ExternalKeyCount uint32

	// InternalKeyCount is the number of internal (change) keys that have been
	// derived.
	InternalKeyCount uint32

	// ImportedKeyCount is the number of imported keys in the account.
	ImportedKeyCount uint32

	// ConfirmedBalance is the total balance of the account from confirmed
	// transactions.
	ConfirmedBalance btcutil.Amount

	// UnconfirmedBalance is the total balance of the account from unconfirmed
	// transactions.
	UnconfirmedBalance btcutil.Amount

	// IsWatchOnly indicates whether the account is in watch-only mode.
	IsWatchOnly bool

	// AddrSchema is the address schema used for the account, if any.
	AddrSchema *waddrmgr.ScopeAddrSchema
}

// CreateAccountParams contains the parameters for creating a new account.
type CreateAccountParams struct {
	// WalletID is the ID of the wallet to create the account in.
	WalletID uint64

	// Scope is the key scope for the new account.
	Scope KeyScope

	// Name is the name of the new account.
	Name string
}

// ImportAccountParams contains the data required to import an account from an
// extended key. This single struct covers normal imports, imports with a
// specific scope, and dry-run imports.
type ImportAccountParams struct {
	// WalletID is the ID of the wallet to import the account into.
	WalletID uint64

	// Name is the name of the account to import.
	Name string

	// AccountKey is the extended key for the account.
	AccountKey *hdkeychain.ExtendedKey

	// MasterKeyFingerprint is the fingerprint of the master key.
	MasterKeyFingerprint uint32

	// AddressType is the address type to use for the account. This is
	// optional and is used to infer the key scope if not provided.
	AddressType *AddressType

	// Scope is an optional key scope for the account. If provided, it
	// overrides any scope inferred from AddressType.
	Scope *KeyScope

	// AddrSchema is an optional address schema for the account.
	AddrSchema *waddrmgr.ScopeAddrSchema

	// DryRun indicates whether this is a dry-run import. If true, no
	// changes will be persisted to the database.
	DryRun bool

	// DryRunNumAddrs is the number of addresses to derive if DryRun is true.
	DryRunNumAddrs uint32
}

// ImportAccountResult holds the results of an account import operation.
type ImportAccountResult struct {
	// AccountProperties contains the properties of the imported account.
	AccountProperties *waddrmgr.AccountProperties

	// ExternalAddrs contains the derived external addresses if the import
	// was a dry run.
	ExternalAddrs []waddrmgr.ManagedAddress

	// InternalAddrs contains the derived internal addresses if the import
	// was a dry run.
	InternalAddrs []waddrmgr.ManagedAddress
}

// GetAccountQuery contains the parameters for querying an account.
type GetAccountQuery struct {
	// WalletID is the ID of the wallet to query.
	WalletID uint64

	// Scope is the key scope of the account.
	Scope KeyScope

	// Name is the name of the account to query.
	Name *string

	// AccountNumber is the number of the account to query.
	AccountNumber *uint32
}

// ListAccountsQuery holds the set of options for a ListAccounts query.
type ListAccountsQuery struct {
	// WalletID is the ID of the wallet to query.
	WalletID uint64

	// Scope is an optional filter to list accounts only for a specific key
	// scope.
	Scope *KeyScope

	// Name is an optional filter to list accounts only with a specific name.
	Name *string
}

// RenameAccountParams contains the parameters for renaming an account. The
// account can be identified by either its old name or its account number.
type RenameAccountParams struct {
	// WalletID is the ID of the wallet containing the account.
	WalletID uint64

	// Scope is the key scope of the account.
	Scope KeyScope

	// OldName is the current name of the account. This is used to identify
	// the account if AccountNumber is not provided.
	OldName string

	// AccountNumber is the number of the account to rename. This is used to
	// identify the account if OldName is not provided.
	AccountNumber *uint32

	// NewName is the new name for the account.
	NewName string
}

// --------------------
// AddressStore Types
// --------------------

// AddressInfo represents a wallet-managed address, including its properties and
// derivation information.
type AddressInfo struct {
	// Address is the human-readable address string.
	Address btcutil.Address

	// Internal indicates whether the address is for internal (change) use.
	Internal bool

	// Compressed indicates whether the address is compressed.
	Compressed bool

	// Used indicates whether the address has been used in a transaction.
	Used bool

	// AddrType is the type of the address (P2PKH, P2SH, etc.).
	AddrType AddressType

	// DerivationInfo contains the BIP-32 derivation path information for the
	// address.
	DerivationInfo DerivationInfo

	// Script is the script associated with the address, if any.
	Script []byte

	// Account is the account number the address belongs to.
	Account uint32
}

// NewAddressParams contains the parameters for creating a new address.
type NewAddressParams struct {
	// WalletID is the ID of the wallet to create the address in.
	WalletID uint64

	// AccountName is the name of the account to create the address for.
	AccountName string

	// Scope is the key scope for the new address.
	Scope KeyScope

	// Change indicates whether to create a change address (true) or an
	// external address (false).
	Change bool
}

// ImportAddressParams encapsulates all the data needed to store a new, imported
// address, script, or private key. The presence of a private key determines
// whether the address will be spendable or watch-only.
type ImportAddressParams struct {
	// WalletID is the ID of the wallet to import the address into.
	WalletID uint64

	// Scope is the key scope for the imported address.
	Scope KeyScope

	// PrivateKey is the private key to import, in WIF format. If this is
	// provided, the address will be spendable. If nil, the import will be
	// watch-only.
	PrivateKey *btcutil.WIF

	// PubKey is the public key to import for a watch-only address. This field
	// is only used if PrivateKey is nil.
	PubKey *btcec.PublicKey

	// Tapscript is the Taproot script to import for a watch-only address.
	// This field is only used if PrivateKey is nil.
	Tapscript *Tapscript

	// Script is the generic script to import for a watch-only address. This
	// field is only used if PrivateKey is nil.
	Script []byte

	// Rescan indicates whether to trigger a rescan after the import.
	Rescan bool

	// RescanFrom is the block stamp from which to start the rescan. This
	// field is only used if Rescan is true.
	RescanFrom *waddrmgr.BlockStamp
}

// GetUnusedAddressQuery contains the parameters for retrieving an unused
// address.
type GetUnusedAddressQuery struct {
	// WalletID is the ID of the wallet to get the address from.
	WalletID uint64

	// AccountName is the name of the account to get the address from.
	AccountName string

	// Scope is the key scope for the address.
	Scope KeyScope

	// Change indicates whether to get a change address.
	Change bool
}

// GetAddressQuery contains the parameters for querying an address.
type GetAddressQuery struct {
	// WalletID is the ID of the wallet to query.
	WalletID uint64

	// Address is the address to query.
	Address btcutil.Address
}

// ListAddressesQuery contains the parameters for listing addresses.
type ListAddressesQuery struct {
	// WalletID is the ID of the wallet to query.
	WalletID uint64

	// AccountName is the name of the account to list addresses for.
	AccountName string

	// Scope is the key scope of the account.
	Scope KeyScope
}

// MarkAddressAsUsedParams contains the parameters for marking an address as
// used.
type MarkAddressAsUsedParams struct {
	// WalletID is the ID of the wallet containing the address.
	WalletID uint64

	// Address is the address to mark as used.
	Address btcutil.Address
}

// DerivationInfo contains the BIP-32 derivation path information for a key.
type DerivationInfo struct {
	// KeyScope is the key scope of the derivation path.
	KeyScope KeyScope

	// MasterKeyFingerprint is the fingerprint of the master key.
	MasterKeyFingerprint uint32

	// Account is the account number of the derivation path.
	Account uint32

	// Branch is the branch number of the derivation path (0 for external, 1
	// for internal).
	Branch uint32

	// Index is the index of the key in the branch.
	Index uint32
}

// --------------------
// TxStore Types
// --------------------

// TxInfo represents the details of a transaction relevant to the wallet.
type TxInfo struct {
	// Hash is the transaction hash.
	Hash chainhash.Hash

	// SerializedTx is the serialized transaction.
	SerializedTx []byte

	// Received is the timestamp when the transaction was received.
	Received time.Time

	// Block contains metadata about the block that includes the transaction.
	Block BlockMeta

	// Credits lists the transaction outputs that are controlled by the
	// wallet.
	Credits []Credit

	// Debits lists the transaction inputs that spend previous wallet
	// outputs.
	Debits []Debit

	// Label is a user-defined label for the transaction.
	Label string
}

// CreateTxParams contains the parameters for creating a new transaction record.
type CreateTxParams struct {
	// WalletID is the ID of the wallet to create the transaction in.
	WalletID uint64

	// Tx is the transaction to record.
	Tx *wire.MsgTx

	// Label is an optional label for the transaction.
	Label string

	// Credits lists the outputs of the transaction that are controlled by the
	// wallet.
	Credits []CreditData
}

// CreditData contains the information needed to record a transaction credit.
type CreditData struct {
	// Index is the output index of the credit.
	Index uint32

	// Address is the address that received the credit.
	Address btcutil.Address
}

// UpdateTxParams contains the parameters for updating a transaction record.
type UpdateTxParams struct {
	// WalletID is the ID of the wallet containing the transaction.
	WalletID uint64

	// TxHash is the hash of the transaction to update.
	TxHash chainhash.Hash

	// Data contains the fields to update.
	Data TxUpdateData
}

// GetTxQuery contains the parameters for querying a transaction.
type GetTxQuery struct {
	// WalletID is the ID of the wallet to query.
	WalletID uint64

	// TxHash is the hash of the transaction to query.
	TxHash chainhash.Hash
}

// ListTxnsQuery contains the parameters for listing transactions.
type ListTxnsQuery struct {
	// WalletID is the ID of the wallet to query.
	WalletID uint64

	// StartHeight is the starting block height for the query.
	StartHeight int32

	// EndHeight is the ending block height for the query.
	EndHeight int32

	// UnminedOnly, if true, will return only unmined (unconfirmed)
	// transactions. If this is set, StartHeight and EndHeight will be ignored.
	UnminedOnly bool
}

// DeleteTxParams contains the parameters for the DeleteTx method.
type DeleteTxParams struct {
	// WalletID is the ID of the wallet containing the transaction.
	WalletID uint64

	// Tx is the transaction to delete.
	Tx *wire.MsgTx
}

// TxUpdateData contains the data required to update a transaction.
type TxUpdateData struct {
	// BlockMeta is the new block metadata for the transaction.
	BlockMeta BlockMeta

	// Label is the new label for the transaction.
	Label string
}

// BlockMeta contains metadata about the block that includes a transaction.
type BlockMeta struct {
	// Hash is the hash of the block.
	Hash chainhash.Hash

	// Height is the height of the block.
	Height int32

	// Time is the timestamp of the block.
	Time time.Time
}

// Credit represents a transaction output that is controlled by the wallet.
type Credit struct {
	// OutPoint is the outpoint of the credit.
	OutPoint wire.OutPoint

	// Amount is the value of the credit.
	Amount btcutil.Amount

	// PkScript is the public key script of the credit.
	PkScript []byte
}

// Debit represents a transaction input that spends a previous wallet output.
type Debit struct {
	// TxIn is the transaction input.
	TxIn wire.TxIn

	// Amount is the value of the input.
	Amount btcutil.Amount
}

// --------------------
// UTXOStore Types
// --------------------

// UtxoInfo represents an unspent transaction output (UTXO).
type UtxoInfo struct {
	// OutPoint is the outpoint of the UTXO.
	OutPoint wire.OutPoint

	// Amount is the value of the UTXO.
	Amount btcutil.Amount

	// PkScript is the public key script of the UTXO.
	PkScript []byte

	// Received is the timestamp when the UTXO was received.
	Received time.Time

	// FromCoinBase indicates whether the UTXO is from a coinbase
	// transaction.
	FromCoinBase bool

	// Height is the block height of the UTXO.
	Height int32
}

// CreateUtxoParams contains the parameters for creating a new UTXO record.
type CreateUtxoParams struct {
	// WalletID is the ID of the wallet to create the UTXO in.
	WalletID uint64

	// Utxo is the UTXO to record.
	Utxo UtxoInfo
}

// GetUtxoQuery contains the parameters for querying a UTXO.
type GetUtxoQuery struct {
	// WalletID is the ID of the wallet to query.
	WalletID uint64

	// OutPoint is the outpoint of the UTXO to query.
	OutPoint wire.OutPoint
}

// DeleteUtxoParams contains the parameters for deleting a UTXO record.
type DeleteUtxoParams struct {
	// WalletID is the ID of the wallet containing the UTXO.
	WalletID uint64

	// OutPoint is the outpoint of the UTXO to delete.
	OutPoint wire.OutPoint
}

// ListUtxosQuery holds the set of options for a ListUTXOs query.
type ListUtxosQuery struct {
	// WalletID is the ID of the wallet to query.
	WalletID uint64

	// Account is an optional filter to list UTXOs only for a specific
	// account.
	Account *uint32

	// MinConfs is the minimum number of confirmations for a UTXO to be
	// included.
	MinConfs int32

	// MaxConfs is the maximum number of confirmations for a UTXO to be
	// included.
	MaxConfs int32
}

// LockUtxoParams contains the parameters for locking a UTXO.
type LockUtxoParams struct {
	// WalletID is the ID of the wallet containing the UTXO.
	WalletID uint64

	// ID is the lock ID for the UTXO.
	ID [32]byte

	// OutPoint is the outpoint of the UTXO to lock.
	OutPoint wire.OutPoint

	// Duration is the duration to lock the UTXO for.
	Duration time.Duration
}

// UnlockUtxoParams contains the parameters for unlocking a UTXO.
type UnlockUtxoParams struct {
	// WalletID is the ID of the wallet containing the UTXO.
	WalletID uint64

	// ID is the lock ID of the UTXO to unlock.
	ID [32]byte

	// OutPoint is the outpoint of the UTXO to unlock.
	OutPoint wire.OutPoint
}

// LeasedOutput represents a UTXO that is currently locked.
type LeasedOutput struct {
	// OutPoint is the outpoint of the locked UTXO.
	OutPoint wire.OutPoint

	// LockID is the ID of the lock.
	LockID LockID

	// Expiration is the time when the lock expires.
	Expiration time.Time
}

// LockID represents a unique context-specific ID assigned to an output lock.
type LockID [32]byte