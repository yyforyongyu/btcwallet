// Package keyvault defines the encryption boundary for wallet key material.
package keyvault

import (
	"context"
	"errors"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

// ErrInvalidPassphrase reports that the provided vault passphrase is wrong.
var ErrInvalidPassphrase = errors.New("invalid vault passphrase")

// ErrVaultLocked reports that an operation requiring unlocked runtime state
// was attempted while the vault was locked.
var ErrVaultLocked = errors.New("vault is locked")

// ErrVaultUnlocked reports that an unlock operation was attempted while the
// vault was already unlocked.
var ErrVaultUnlocked = errors.New("vault is already unlocked")

// ChangePassphraseParams describes an atomic rotation of the public and/or
// private passphrase guarding a vault. The public and private rotations are
// independent: either or both may be requested in a single call.
type ChangePassphraseParams struct {
	// ChangePublic indicates the public passphrase should be rotated from
	// PublicOld to PublicNew.
	ChangePublic bool

	// PublicOld is the current public passphrase. It is only consulted when
	// ChangePublic is true.
	PublicOld []byte

	// PublicNew is the desired public passphrase. It is only used when
	// ChangePublic is true.
	PublicNew []byte

	// ChangePrivate indicates the private passphrase should be rotated from
	// PrivateOld to PrivateNew.
	ChangePrivate bool

	// PrivateOld is the current private passphrase. It is only consulted
	// when ChangePrivate is true.
	PrivateOld []byte

	// PrivateNew is the desired private passphrase. It is only used when
	// ChangePrivate is true.
	PrivateNew []byte
}

// Vault manages the lock lifecycle and cryptographic operations for wallet key
// material.
type Vault interface {
	// Unlock unlocks the vault with the provided passphrase.
	//
	// If the passphrase is invalid, or the unlock operation fails, the vault
	// must remain locked. If Unlock is called while the vault is already
	// unlocked, it must return ErrVaultUnlocked without validating the provided
	// passphrase.
	Unlock(ctx context.Context, passphrase []byte) error

	// Lock locks the vault and erases secret material from memory. Lock is
	// idempotent.
	Lock()

	// IsLocked reports whether the vault is currently locked.
	IsLocked() bool

	// Encrypt encrypts plaintext key material with the selected crypto key
	// type.
	Encrypt(keyType waddrmgr.CryptoKeyType, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext key material with the selected crypto key
	// type.
	Decrypt(keyType waddrmgr.CryptoKeyType, ciphertext []byte) ([]byte, error)

	// ChangePassphrase rotates persisted wallet secrets to the new
	// passphrase(s) described by params. The implementation preserves the
	// vault's original locked/unlocked state: an unlocked vault stays
	// unlocked with its runtime keys unchanged, and a locked vault leaves no
	// decrypted state behind.
	ChangePassphrase(ctx context.Context, params ChangePassphraseParams) error
}
