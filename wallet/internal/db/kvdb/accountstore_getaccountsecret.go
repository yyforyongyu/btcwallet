package kvdb

import (
	"context"
	"errors"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

// accountSecretReader is the narrow slice of *waddrmgr.ScopedKeyManager that
// GetAccountSecret needs. The scoped-manager methods that export encrypted
// account material live on the concrete type rather than the AccountStore
// interface, so kvdb asserts to this local interface (mirroring
// derivedAccountKeyDeriver) instead of widening AccountStore.
type accountSecretReader interface {
	// AccountSecret returns the account-level extended public key, the
	// stored encrypted private key ciphertext (nil when watch-only or
	// imported), the master-key fingerprint, the account name, and whether
	// the account is imported.
	AccountSecret(ns walletdb.ReadBucket, account uint32) (
		*hdkeychain.ExtendedKey, []byte, uint32, string, bool, error)
}

// GetAccountSecret retrieves encrypted account-level signing material for one
// account. kvdb resolves the account through the waddrmgr scoped key manager:
// the AccountID and AccountNumber selectors both map to the durable walletdb
// account number, while Name resolves to a number through the scoped manager's
// name lookup.
func (s *Store) GetAccountSecret(_ context.Context,
	query db.GetAccountSecretQuery) (*db.AccountSecret, error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	scope := waddrmgr.KeyScope{
		Purpose: query.Scope.Purpose,
		Coin:    query.Scope.Coin,
	}

	var secret *db.AccountSecret

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return db.ErrAccountNotFound
		}

		var err error

		secret, err = s.buildAccountSecret(ns, scope, query)

		return err
	})
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// buildAccountSecret resolves the query's account within the given namespace
// and scope and assembles its encrypted secret material. It is the read body
// of GetAccountSecret, factored out so the exported method stays thin.
func (s *Store) buildAccountSecret(ns walletdb.ReadBucket,
	scope waddrmgr.KeyScope,
	query db.GetAccountSecretQuery) (*db.AccountSecret, error) {

	scopedMgr, err := s.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, translateAccountErr(err, db.ErrAccountNotFound)
	}

	num, err := resolveAccountSecretNumber(ns, scopedMgr, query)
	if err != nil {
		return nil, err
	}

	reader, ok := scopedMgr.(accountSecretReader)
	if !ok {
		return nil, errScopedAccountSecretUnsupported
	}

	pubKey, encPriv, fingerprint, name, _, err := reader.AccountSecret(
		ns, num,
	)
	if err != nil {
		return nil, translateAccountErr(err, db.ErrAccountNotFound)
	}

	// Keep the fingerprint consistent with GetAccount and the SQL backend:
	// derived accounts persist the wallet root fingerprint in the kvdb side
	// bucket (waddrmgr's default-account row has no fingerprint column and
	// AccountSecret reports 0 for it), while imported (watch-only) accounts
	// carry it on the waddrmgr row, which AccountSecret already returns.
	persisted, present, err := getAccountMasterFingerprint(ns, scope, num)
	if err != nil {
		return nil, err
	}

	if present {
		fingerprint = persisted
	}

	var publicKey []byte
	if pubKey != nil {
		publicKey = []byte(pubKey.String())
	}

	return &db.AccountSecret{
		WalletID:             query.WalletID,
		Scope:                query.Scope,
		AccountNumber:        num,
		AccountName:          name,
		PublicKey:            publicKey,
		EncryptedPrivateKey:  encPriv,
		MasterKeyFingerprint: fingerprint,
	}, nil
}

// resolveAccountSecretNumber maps the query's single account selector to a
// waddrmgr account number. AccountID and AccountNumber are the durable
// walletdb account number in kvdb, so both are used verbatim; Name resolves
// through the scoped manager's name lookup.
func resolveAccountSecretNumber(ns walletdb.ReadBucket,
	scopedMgr waddrmgr.AccountStore,
	query db.GetAccountSecretQuery) (uint32, error) {

	switch {
	case query.AccountNumber != nil:
		return *query.AccountNumber, nil

	case query.AccountID != nil:
		return *query.AccountID, nil

	default:
		num, err := scopedMgr.LookupAccount(ns, *query.Name)
		if err != nil {
			return 0, translateAccountErr(err, db.ErrAccountNotFound)
		}

		return num, nil
	}
}

// errScopedAccountSecretUnsupported is returned when a mocked or alternate
// scoped manager does not expose kvdb's encrypted-account-secret reader.
var errScopedAccountSecretUnsupported = errors.New(
	"kvdb: scoped account secret export unsupported",
)

// compile-time guard: the concrete waddrmgr scoped manager satisfies the
// narrow reader interface GetAccountSecret asserts to.
var _ accountSecretReader = (*waddrmgr.ScopedKeyManager)(nil)
