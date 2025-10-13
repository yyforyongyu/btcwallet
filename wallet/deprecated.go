//nolint:ll
package wallet

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// NextAccount creates the next account and returns its account number.  The
// name must be unique to the account.  In order to support automatic seed
// restoring, new accounts may not be created when all of the previous 100
// accounts have no transaction history (this is a deviation from the BIP0044
// spec, which allows no unused account gaps).
func (w *Wallet) NextAccount(scope waddrmgr.KeyScope, name string) (uint32, error) {
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	params := db.CreateAccountParams{
		WalletID: w.ID(),
		Scope:    dbScope,
		Name:     name,
	}
	info, err := w.store.CreateAccount(context.Background(), params)
	if err != nil {
		return 0, err
	}

	info, err = w.store.GetAccount(context.Background(), db.GetAccountQuery{
		Scope: dbScope,
		Name:  &name,
	})
	if err != nil {
		log.Errorf("Cannot fetch new account properties for notification "+
			"after account creation: %v", err)
	} else {
		w.NtfnServer.notifyAccountProperties(&waddrmgr.AccountProperties{
			AccountNumber:    info.AccountNumber,
			AccountName:      info.AccountName,
			ExternalKeyCount: info.ExternalKeyCount,
			InternalKeyCount: info.InternalKeyCount,
			ImportedKeyCount: info.ImportedKeyCount,
		})
	}

	return info.AccountNumber, nil
}

// Accounts returns the current names, numbers, and total balances of all
// accounts in the wallet restricted to a particular key scope.  The current
// chain tip is included in the result for atomicity reasons.
//
// TODO(jrick): Is the chain tip really needed, since only the total balances
// are included?
func (w *Wallet) Accounts(scope waddrmgr.KeyScope) (*AccountsResult, error) {
	walletInfo, err := w.store.GetWallet(context.Background(), w.Name())
	if err != nil {
		return nil, err
	}
	syncBlock := walletInfo.SyncState
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	accounts, err := w.store.ListAccounts(context.Background(), db.ListAccountsQuery{
		WalletID: w.ID(),
		Scope:    &dbScope,
	})
	if err != nil {
		return nil, err
	}

	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   syncBlock.SyncedTo,
		CurrentBlockHeight: syncBlock.Height,
	}, err
}

// RenameAccountDeprecated sets the name for an account number to newName.
func (w *Wallet) RenameAccountDeprecated(scope waddrmgr.KeyScope,
	account uint32, newName string) error {

	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	err := w.store.UpdateAccountName(context.Background(), db.UpdateAccountNameParams{
		WalletID: w.ID(),
		Scope:    dbScope,
		OldName:  "", // TODO(yy): fix this
		NewName:  newName,
	})
	if err != nil {
		return err
	}

	info, err := w.store.GetAccount(context.Background(), db.GetAccountQuery{
		Scope: dbScope,
		Name:  &newName,
	})
	if err == nil {
		w.NtfnServer.notifyAccountProperties(&waddrmgr.AccountProperties{
			AccountNumber:    info.AccountNumber,
			AccountName:      info.AccountName,
			ExternalKeyCount: info.ExternalKeyCount,
			InternalKeyCount: info.InternalKeyCount,
			ImportedKeyCount: info.ImportedKeyCount,
		})
	}

	return err
}

// ScriptForOutputDeprecated returns the address, witness program and redeem
// script for a given UTXO. An error is returned if the UTXO does not belong to
// our wallet or it is not a managed pubKey address.
//
// Deprecated: Use AddressManager.ScriptForOutput instead.
func (w *Wallet) ScriptForOutputDeprecated(output *wire.TxOut) (
	waddrmgr.ManagedPubKeyAddress, []byte, []byte, error) {

	script, err := w.ScriptForOutput(context.Background(), *output)
	if err != nil {
		return nil, nil, nil, err
	}

	// This is a messy conversion.
	// TODO(yy): clean this up.
	info, err := w.store.GetAddress(context.Background(), db.GetAddressQuery{
		WalletID: w.ID(),
		Address:  script.Addr.Address,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	var managedAddr waddrmgr.ManagedAddress = &managedAddress{info: info}
	pubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, nil, nil, fmt.Errorf("%w: addr %s",
			ErrNotPubKeyAddress, script.Addr.Address)
	}

	return pubKeyAddr, script.WitnessProgram, script.RedeemScript, nil
}

// ComputeInputScript generates a complete InputScript for the passed
// transaction with the signature as defined within the passed SignDescriptor.
// This method is capable of generating the proper input script for both
// regular p2wkh output and p2wkh outputs nested within a regular p2sh output.
func (w *Wallet) ComputeInputScript(tx *wire.MsgTx, output *wire.TxOut,
	inputIndex int, sigHashes *txscript.TxSigHashes,
	hashType txscript.SigHashType, tweaker PrivKeyTweaker) (wire.TxWitness,
	[]byte, error) {

	walletAddr, witnessProgram, sigScript, err := w.ScriptForOutputDeprecated(output)
	if err != nil {
		return nil, nil, err
	}

	privKey, err := walletAddr.PrivKey()
	if err != nil {
		return nil, nil, err
	}

	// If we need to maybe tweak our private key, do it now.
	if tweaker != nil {
		privKey, err = tweaker(privKey)
		if err != nil {
			return nil, nil, err
		}
	}

	// We need to produce a Schnorr signature for p2tr key spend addresses.
	if txscript.IsPayToTaproot(output.PkScript) {
		// We can now generate a valid witness which will allow us to
		// spend this output.
		witnessScript, err := txscript.TaprootWitnessSignature(
			tx, sigHashes, inputIndex, output.Value,
			output.PkScript, hashType, privKey,
		)
		if err != nil {
			return nil, nil, err
		}

		return witnessScript, nil, nil
	}

	// Generate a valid witness stack for the input.
	witnessScript, err := txscript.WitnessSignature(
		tx, sigHashes, inputIndex, output.Value, witnessProgram,
		hashType, privKey, true,
	)
	if err != nil {
		return nil, nil, err
	}

	return witnessScript, sigScript, nil
}