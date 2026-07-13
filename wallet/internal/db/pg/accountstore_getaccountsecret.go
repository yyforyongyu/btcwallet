package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// GetAccountSecret retrieves encrypted account-level signing material for one
// account.
func (s *Store) GetAccountSecret(ctx context.Context,
	query db.GetAccountSecretQuery) (*db.AccountSecret, error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	if query.AccountID != nil {
		return s.getAccountSecretByID(ctx, query)
	}

	var secret *db.AccountSecret

	err = s.execRead(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetAccountSecret(ctx, sqlc.GetAccountSecretParams{
			WalletID:      int64(query.WalletID),
			Purpose:       int64(query.Scope.Purpose),
			CoinType:      int64(query.Scope.Coin),
			AccountNumber: db.NullableUint32ToSQLInt64(query.AccountNumber),
			AccountName:   db.NullableStringToSQLNullString(query.Name),
		})
		if err != nil {
			return mapGetAccountSecretErr(err, query)
		}

		secret, err = accountSecretRowToInfo(row)

		return err
	})
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// getAccountSecretByID resolves account-level signing material through the
// accounts.id selector. A missing account row maps to db.ErrAccountNotFound.
func (s *Store) getAccountSecretByID(ctx context.Context,
	query db.GetAccountSecretQuery) (*db.AccountSecret, error) {

	var secret *db.AccountSecret

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetAccountSecretById(
			ctx, sqlc.GetAccountSecretByIdParams{
				WalletID: int64(query.WalletID),
				ID:       int64(*query.AccountID),
			},
		)
		if err != nil {
			return mapGetAccountSecretErr(err, query)
		}

		secret, err = accountSecretRowToInfo(row)

		return err
	})
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// accountSecretRow is a type constraint union of the PostgreSQL account-secret
// row types that share the same field structure, letting a single generic
// conversion handle both the scope-selector and account-id-selector queries.
type accountSecretRow interface {
	sqlc.GetAccountSecretRow | sqlc.GetAccountSecretByIdRow
}

// accountSecretRowToInfo converts a PostgreSQL account-secret row to the
// backend-independent AccountSecret shape.
func accountSecretRowToInfo[T accountSecretRow](
	row T) (*db.AccountSecret, error) {

	var (
		walletID            int64
		purpose             int64
		coinType            int64
		accountNumber       sql.NullInt64
		accountName         string
		publicKey           []byte
		encryptedPrivateKey []byte
		masterFingerprint   sql.NullInt64
	)

	switch base := any(row).(type) {
	case sqlc.GetAccountSecretRow:
		walletID = base.WalletID
		purpose = base.Purpose
		coinType = base.CoinType
		accountNumber = base.AccountNumber
		accountName = base.AccountName
		publicKey = base.PublicKey
		encryptedPrivateKey = base.EncryptedPrivateKey
		masterFingerprint = base.MasterFingerprint

	case sqlc.GetAccountSecretByIdRow:
		walletID = base.WalletID
		purpose = base.Purpose
		coinType = base.CoinType
		accountNumber = base.AccountNumber
		accountName = base.AccountName
		publicKey = base.PublicKey
		encryptedPrivateKey = base.EncryptedPrivateKey
		masterFingerprint = base.MasterFingerprint
	}

	walletIDVal, err := db.Int64ToUint32(walletID)
	if err != nil {
		return nil, fmt.Errorf("wallet ID: %w", err)
	}

	purposeVal, err := db.Int64ToUint32(purpose)
	if err != nil {
		return nil, fmt.Errorf("scope purpose: %w", err)
	}

	coin, err := db.Int64ToUint32(coinType)
	if err != nil {
		return nil, fmt.Errorf("scope coin type: %w", err)
	}

	var accountNumberVal uint32
	if accountNumber.Valid {
		accountNumberVal, err = db.Int64ToUint32(accountNumber.Int64)
		if err != nil {
			return nil, fmt.Errorf("account number: %w", err)
		}
	}

	var masterFingerprintVal uint32
	if masterFingerprint.Valid {
		masterFingerprintVal, err = db.Int64ToUint32(
			masterFingerprint.Int64,
		)
		if err != nil {
			return nil, fmt.Errorf("master fingerprint: %w", err)
		}
	}

	return &db.AccountSecret{
		WalletID: walletIDVal,
		Scope: db.KeyScope{
			Purpose: purposeVal, Coin: coin,
		},
		AccountNumber:        accountNumberVal,
		AccountName:          accountName,
		PublicKey:            publicKey,
		EncryptedPrivateKey:  encryptedPrivateKey,
		MasterKeyFingerprint: masterFingerprintVal,
	}, nil
}

// mapGetAccountSecretErr returns the typed ErrAccountNotFound when err is
// sql.ErrNoRows, falling back to a wrapped form otherwise.
func mapGetAccountSecretErr(err error,
	query db.GetAccountSecretQuery) error {

	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("get account secret: %w", err)
	}

	switch {
	case query.AccountID != nil:
		return fmt.Errorf("account id %d in wallet %d: %w",
			*query.AccountID, query.WalletID, db.ErrAccountNotFound)

	case query.Name != nil:
		return fmt.Errorf("account %q in scope %d/%d: %w", *query.Name,
			query.Scope.Purpose, query.Scope.Coin,
			db.ErrAccountNotFound)

	default:
		return fmt.Errorf("account %d in scope %d/%d: %w",
			*query.AccountNumber, query.Scope.Purpose,
			query.Scope.Coin, db.ErrAccountNotFound)
	}
}
