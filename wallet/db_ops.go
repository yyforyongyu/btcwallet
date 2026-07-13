// Package wallet provides the implementation of a Bitcoin wallet.
//
// TODO(yy): This file will be removed once the Store implementation is
// finished.
package wallet

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
)

// changeStorePassphrase rotates the private passphrase for a store-backed
// (non-legacy) wallet through the key vault, which owns the encryption
// boundary for the wallet's secret material and preserves the vault's current
// locked/unlocked state.
func (w *Wallet) changeStorePassphrase(ctx context.Context,
	req ChangePassphraseRequest) error {

	if w.keyVault == nil {
		return fmt.Errorf("%w: keyVault", ErrMissingParam)
	}

	err := w.keyVault.ChangePassphrase(ctx, keyvault.ChangePassphraseParams{
		ChangePublic:  req.ChangePublic,
		PublicOld:     req.PublicOld,
		PublicNew:     req.PublicNew,
		ChangePrivate: req.ChangePrivate,
		PrivateOld:    req.PrivateOld,
		PrivateNew:    req.PrivateNew,
	})
	if err != nil {
		return fmt.Errorf("change store passphrase: %w", err)
	}

	return nil
}

// DBPutPassphrase updates the wallet's public or private passphrases.
//
// TODO(yy): Refactor this in the `Store` implementation - we can call
// `UpdateWallet` instead.
func (w *Wallet) DBPutPassphrase(ctx context.Context,
	req ChangePassphraseRequest) error {

	if w.legacyStore == nil {
		return w.changeStorePassphrase(ctx, req)
	}

	err := w.legacyStore.ChangePassphrase(ctx, kvdb.ChangePassphraseParams{
		ChangePublic:  req.ChangePublic,
		PublicOld:     req.PublicOld,
		PublicNew:     req.PublicNew,
		ChangePrivate: req.ChangePrivate,
		PrivateOld:    req.PrivateOld,
		PrivateNew:    req.PrivateNew,
	})
	if err != nil {
		return fmt.Errorf("change legacy passphrase: %w", err)
	}

	return nil
}
