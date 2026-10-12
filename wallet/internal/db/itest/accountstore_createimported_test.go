//go:build itest

package itest

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/stretchr/testify/require"
)

// TestCreateImportedAccountRejectsWalletScopeMismatch verifies that the
// composite wallet/scope invariant is enforced by the database on direct
// imported-account inserts.
func TestCreateImportedAccountRejectsWalletScopeMismatch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	firstWalletID := newWallet(
		t, store, "wallet-raw-imported-account-mismatch-a",
	)
	secondWalletID := newWallet(
		t, store, "wallet-raw-imported-account-mismatch-b",
	)
	CreateImportedAccount(
		t, store, firstWalletID, db.KeyScopeBIP0084, "seed-imported-scope",
		false,
	)

	firstScopeID := GetKeyScopeID(t, queries, firstWalletID, db.KeyScopeBIP0084)

	err := createImportedAccountRaw(
		t, store.DB(), secondWalletID, firstScopeID, "raw-imported-mismatch",
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "constraint")
}

// TestCreateImportedAccountIdentityIndex verifies that the database itself
// rejects a matching branch identity while admitting a disjoint scope schema.
func TestCreateImportedAccountIdentityIndex(t *testing.T) {
	t.Parallel()

	// Arrange: create three account rows through the Store with opaque keys,
	// leaving their normalized fields empty for direct database writes.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "identity-index")
	strict := db.ScopeAddrSchema{
		ExternalAddrType: db.NestedWitnessPubKey,
		InternalAddrType: db.NestedWitnessPubKey,
	}
	requests := []db.CreateImportedAccountParams{
		{
			WalletID:            walletID,
			Name:                "owner",
			Scope:               db.KeyScopeBIP0084,
			PublicKey:           RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
		},
		{
			WalletID:            walletID,
			Name:                "overlap",
			Scope:               db.KeyScopeBIP0049Plus,
			PublicKey:           RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
		},
		{
			WalletID:            walletID,
			Name:                "disjoint",
			Scope:               db.KeyScope{Purpose: 100, Coin: 0},
			AddrSchema:          &strict,
			PublicKey:           RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
		},
	}
	ids := make([]int64, 0, len(requests))

	for _, request := range requests {
		info, err := store.CreateImportedAccount(t.Context(), request)
		require.NoError(t, err)
		require.NotNil(t, info.AccountID)
		ids = append(ids, int64(*info.AccountID))
	}

	// Bind the same raw normalized payload to each persisted scope schema.
	// PostgreSQL and SQLite differ only in parameter placeholder syntax.
	bind := [3]string{"?", "?", "?"}
	if testBackend() == dberr.BackendPostgres {
		bind = [3]string{"$1", "$2", "$3"}
	}

	statement := fmt.Sprintf(`
		UPDATE accounts SET
			chain_code = %s, compressed_pub_key = %s,
			external_type_id = (
				SELECT external_type_id FROM key_scopes
				WHERE id = accounts.scope_id
			),
			internal_type_id = (
				SELECT internal_type_id FROM key_scopes
				WHERE id = accounts.scope_id
			)
		WHERE id = %s`, bind[0], bind[1], bind[2])
	chainCode := bytes.Repeat([]byte{0x11}, 32)
	pubKey := bytes.Repeat([]byte{0x22}, 33)

	// Act: populate the owner first, then try matching keys in an overlapping
	// scope and in a scope whose corresponding branches are both disjoint.
	_, ownerErr := store.DB().ExecContext(
		t.Context(), statement, chainCode, pubKey, ids[0],
	)
	_, overlapErr := store.DB().ExecContext(
		t.Context(), statement, chainCode, pubKey, ids[1],
	)
	_, disjointErr := store.DB().ExecContext(
		t.Context(), statement, chainCode, pubKey, ids[2],
	)

	// Assert: the unique branch index refuses only the overlapping identity;
	// the disjoint row remains writable with the very same key payload.
	require.NoError(t, ownerErr)
	require.Error(t, overlapErr)
	require.NoError(t, disjointErr)
}

// TestCreateImportedAccountErrors verifies that CreateImportedAccount returns
// appropriate errors for invalid inputs.
func TestCreateImportedAccountErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		params  db.CreateImportedAccountParams
		wantErr error
	}{
		{
			name: "missing name",
			params: db.CreateImportedAccountParams{
				Name:                "",
				Scope:               db.KeyScopeBIP0084,
				PublicKey:           RandomBytes(32),
				EncryptedPrivateKey: RandomBytes(32),
			},
			wantErr: db.ErrMissingAccountName,
		},
		{
			name: "missing public key",
			params: db.CreateImportedAccountParams{
				Name:                "missing-pubkey",
				Scope:               db.KeyScopeBIP0084,
				PublicKey:           nil,
				EncryptedPrivateKey: RandomBytes(32),
			},
			wantErr: db.ErrMissingAccountPublicKey,
		},
		{
			name: "unknown scope",
			params: db.CreateImportedAccountParams{
				Name:                "unknown-scope",
				Scope:               db.KeyScope{Purpose: 999, Coin: 999},
				PublicKey:           RandomBytes(32),
				EncryptedPrivateKey: RandomBytes(32),
			},
			wantErr: db.ErrUnknownKeyScope,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)
			walletID := newWallet(t, store, tc.name+"-wallet")
			tc.params.WalletID = walletID

			props, err := store.CreateImportedAccount(t.Context(), tc.params)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, props)
		})
	}
}

// TestCreateImportedAccountPersistsNoChainSync verifies both policy values pass
// through the real SQL imported-account create and read paths unchanged.
func TestCreateImportedAccountPersistsNoChainSync(t *testing.T) {
	t.Parallel()

	// Arrange: create one isolated spendable wallet and two valid imported
	// account requests that differ only in the policy value being persisted.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "imported-no-chain-sync-wallet")
	falseParams := db.CreateImportedAccountParams{
		WalletID:            walletID,
		Name:                "imported-policy-false",
		Scope:               db.KeyScopeBIP0084,
		PublicKey:           RandomBytes(32),
		EncryptedPrivateKey: RandomBytes(32),
		NoChainSync:         false,
	}
	trueParams := db.CreateImportedAccountParams{
		WalletID:            walletID,
		Name:                "imported-policy-true",
		Scope:               db.KeyScopeBIP0084,
		PublicKey:           RandomBytes(32),
		EncryptedPrivateKey: RandomBytes(32),
		NoChainSync:         true,
	}

	// Act: create both accounts and independently reload each row through the
	// normal Store read path.
	createdFalse, createFalseErr := store.CreateImportedAccount(
		t.Context(), falseParams,
	)
	createdTrue, createTrueErr := store.CreateImportedAccount(
		t.Context(), trueParams,
	)
	loadedFalse, loadFalseErr := store.GetAccount(
		t.Context(), getAccountQueryByName(
			walletID, falseParams.Scope, falseParams.Name,
		),
	)
	loadedTrue, loadTrueErr := store.GetAccount(
		t.Context(), getAccountQueryByName(
			walletID, trueParams.Scope, trueParams.Name,
		),
	)

	// Assert: both creation results and both fresh reads retain their exact
	// values, covering the default and non-default policies equally.
	require.NoError(t, createFalseErr)
	require.NoError(t, createTrueErr)
	require.NoError(t, loadFalseErr)
	require.NoError(t, loadTrueErr)
	require.False(t, createdFalse.NoChainSync)
	require.True(t, createdTrue.NoChainSync)
	require.False(t, loadedFalse.NoChainSync)
	require.True(t, loadedTrue.NoChainSync)
}

// TestCreateImportedAccountMissingWallet verifies that CreateImportedAccount
// returns ErrWalletNotFound when the wallet does not exist.
func TestCreateImportedAccountMissingWallet(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := db.CreateImportedAccountParams{
		WalletID:            99999,
		Name:                "missing-wallet-imported",
		Scope:               db.KeyScopeBIP0084,
		PublicKey:           RandomBytes(32),
		EncryptedPrivateKey: RandomBytes(32),
	}

	props, err := store.CreateImportedAccount(t.Context(), params)
	require.ErrorIs(t, err, db.ErrWalletNotFound)
	require.Nil(t, props)
}

// TestCreateImportedAccountValidationPrecedesWalletLookup verifies that basic
// input validation still wins over wallet lookup failures.
func TestCreateImportedAccountValidationPrecedesWalletLookup(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	props, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:            99999,
			Name:                "",
			Scope:               db.KeyScopeBIP0084,
			PublicKey:           RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
		},
	)
	require.ErrorIs(t, err, db.ErrMissingAccountName)
	require.Nil(t, props)
}

// TestCreateImportedAccountDuplicateName verifies that creating an imported
// account with a duplicate name in the same scope fails.
func TestCreateImportedAccountDuplicateName(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	walletID := newWallet(t, store, "imported-duplicate-name-wallet")

	params := db.CreateImportedAccountParams{
		WalletID:            walletID,
		Name:                "duplicate-imported",
		Scope:               db.KeyScopeBIP0084,
		PublicKey:           RandomBytes(32),
		EncryptedPrivateKey: RandomBytes(32),
	}

	_, err := store.CreateImportedAccount(t.Context(), params)
	require.NoError(t, err)

	// Attempt to create second imported account with same name in same
	// scope.
	params.PublicKey = RandomBytes(32)
	_, err = store.CreateImportedAccount(t.Context(), params)
	require.Error(t, err)
	require.ErrorContains(t, err, "constraint")
}

// TestCreateImportedAccountIdentity tests script ownership admission through
// the concrete Store, including metadata normalization and disjoint branches.
func TestCreateImportedAccountIdentity(t *testing.T) {
	t.Parallel()

	// Arrange: construct equal payloads with different serialization metadata,
	// plus independent public-key and chain-code changes for allowed controls.
	master, err := hdkeychain.NewMaster(
		bytes.Repeat([]byte{0xCC}, 32), &chaincfg.SimNetParams,
	)
	require.NoError(t, err)
	key, err := master.Neuter()
	require.NoError(t, err)
	pub, err := key.ECPubKey()
	require.NoError(t, err)

	alias := hdkeychain.NewExtendedKey(
		chaincfg.MainNetParams.HDPublicKeyID[:], pub.SerializeCompressed(),
		key.ChainCode(), []byte{1, 2, 3, 4}, 3, 42, false,
	)
	other, err := key.Derive(1)
	require.NoError(t, err)

	otherChain := hdkeychain.NewExtendedKey(
		chaincfg.MainNetParams.HDPublicKeyID[:], pub.SerializeCompressed(),
		bytes.Repeat([]byte{0xDD}, 32), []byte{1, 2, 3, 4}, 3, 42, false,
	)
	plus := db.ScopeAddrMap[db.KeyScopeBIP0049Plus]
	strict := db.ScopeAddrSchema{
		ExternalAddrType: db.NestedWitnessPubKey,
		InternalAddrType: db.NestedWitnessPubKey,
	}
	swapped := db.ScopeAddrSchema{
		ExternalAddrType: db.WitnessPubKey,
		InternalAddrType: db.NestedWitnessPubKey,
	}

	tests := []struct {
		name        string
		ownerScope  db.KeyScope
		ownerSchema *db.ScopeAddrSchema
		scope       db.KeyScope
		schema      *db.ScopeAddrSchema
		key         string
		dryRun      bool
		want        error
	}{
		{
			name:       "same scope",
			ownerScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0084,
			key:        alias.String(),
			want:       db.ErrAccountIdentityCollision,
		},
		{
			name:       "internal overlap across scopes",
			ownerScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0049Plus,
			key:        alias.String(),
			want:       db.ErrAccountIdentityCollision,
		},
		{
			name:       "strict nested disjoint",
			ownerScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0049Plus,
			schema:     &strict,
			key:        alias.String(),
		},
		{
			name:        "external overlap",
			ownerScope:  db.KeyScopeBIP0049Plus,
			ownerSchema: &strict,
			scope:       db.KeyScope{Purpose: 100, Coin: 0},
			schema:      &plus,
			key:         alias.String(),
			want:        db.ErrAccountIdentityCollision,
		},
		{
			name:       "cross branch equality is disjoint",
			ownerScope: db.KeyScopeBIP0049Plus,
			scope:      db.KeyScope{Purpose: 100, Coin: 0},
			schema:     &swapped,
			key:        alias.String(),
		},
		{
			name:       "different payload",
			ownerScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0084,
			key:        other.String(),
		},
		{
			name:       "same pubkey different chain code",
			ownerScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0084,
			key:        otherChain.String(),
		},
		{
			name:       "preview collision",
			ownerScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0084,
			key:        alias.String(),
			dryRun:     true,
			want:       db.ErrAccountIdentityCollision,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: the existing owner has no children and is excluded
			// from chain sync, which must not hide its script ownership.
			store := NewTestStore(t)
			walletID := newWallet(t, store, "identity")
			owner := db.CreateImportedAccountParams{
				WalletID:            walletID,
				Name:                "owner",
				Scope:               tc.ownerScope,
				AddrSchema:          tc.ownerSchema,
				PublicKey:           []byte(key.String()),
				EncryptedPrivateKey: RandomBytes(32),
				NoChainSync:         true,
			}
			_, err := store.CreateImportedAccount(t.Context(), owner)
			require.NoError(t, err)

			query := db.ListAccountsQuery{
				WalletID:    walletID,
				SkipBalance: true,
			}
			before, err := store.ListAccounts(t.Context(), query)
			require.NoError(t, err)

			candidate := owner
			candidate.Name, candidate.PublicKey = "candidate", []byte(tc.key)
			candidate.Scope, candidate.AddrSchema = tc.scope, tc.schema
			candidate.MasterFingerprint, candidate.DryRun = 123, tc.dryRun

			// Act: attempt the second import within the real SQL write.
			info, err := store.CreateImportedAccount(t.Context(), candidate)

			// Assert: collisions return no row and no secret or child/watch
			// fact; disjoint identities remain admitted with their secrets.
			require.ErrorIs(t, err, tc.want)
			after, err := store.ListAccounts(t.Context(), query)
			require.NoError(t, err)

			if tc.want != nil {
				require.Nil(t, info)
				require.Equal(t, before, after)
			} else {
				require.NotNil(t, info)
				require.Len(t, after, 2)
			}

			var secrets, addresses, children int

			err = store.DB().QueryRowContext(t.Context(), `
				SELECT (SELECT count(*) FROM account_secrets),
				       (SELECT count(*) FROM addresses),
				       (SELECT count(*) FROM derived_addresses)
			`).Scan(&secrets, &addresses, &children)
			require.NoError(t, err)
			require.Equal(t, len(after), secrets)
			require.Zero(t, addresses)
			require.Zero(t, children)
		})
	}
}

// TestCreateImportedAccountIdentityNamePrecedence verifies that an occupied
// name wins over an overlapping account identity on both SQL stores.
func TestCreateImportedAccountIdentityNamePrecedence(t *testing.T) {
	t.Parallel()

	// Arrange: use one real XPub for an existing imported account and the
	// repeated request, making both the name and script identity occupied.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "identity-name-precedence")
	master, err := hdkeychain.NewMaster(
		bytes.Repeat([]byte{0xCE}, 32), &chaincfg.SimNetParams,
	)
	require.NoError(t, err)
	key, err := master.Neuter()
	require.NoError(t, err)

	params := db.CreateImportedAccountParams{
		WalletID:            walletID,
		Scope:               db.KeyScopeBIP0084,
		Name:                "owner",
		PublicKey:           []byte(key.String()),
		EncryptedPrivateKey: RandomBytes(32),
	}
	_, err = store.CreateImportedAccount(t.Context(), params)
	require.NoError(t, err)

	query := db.ListAccountsQuery{
		WalletID:    walletID,
		SkipBalance: true,
	}
	before, err := store.ListAccounts(t.Context(), query)
	require.NoError(t, err)

	// Act: retry the occupied request to check classification stability.
	for range 2 {
		info, err := store.CreateImportedAccount(t.Context(), params)

		// Assert: each request reports the name conflict and creates no row.
		require.ErrorIs(t, err, db.ErrAccountNameConflict)
		require.Nil(t, info)
	}

	// Assert: neither retry changes the visible account inventory.
	after, err := store.ListAccounts(t.Context(), query)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

// TestCreateImportedAccountIdentityConcurrent checks wallet-wide admission
// when competing imports start together, including duplicate-name precedence.
func TestCreateImportedAccountIdentityConcurrent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope db.KeyScope
		other string
		want  error
	}{
		{
			name:  "same scope",
			scope: db.KeyScopeBIP0084,
			other: "second",
			want:  db.ErrAccountIdentityCollision,
		},
		{
			name:  "cross scope",
			scope: db.KeyScopeBIP0049Plus,
			other: "second",
			want:  db.ErrAccountIdentityCollision,
		},
		{
			name:  "occupied name",
			scope: db.KeyScopeBIP0084,
			other: "first",
			want:  db.ErrAccountNameConflict,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: fresh SQL storage and a real XPub isolate each race;
			// buffered results and a bounded context let both workers exit.
			store := NewTestStore(t)
			walletID := newWatchOnlyWallet(t, store, "identity-race")
			key, err := hdkeychain.NewMaster(
				RandomBytes(32), &chaincfg.SimNetParams,
			)
			require.NoError(t, err)
			pub, err := key.Neuter()
			require.NoError(t, err)

			start := make(chan struct{})
			results := make(chan error, 2)

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			for _, params := range []db.CreateImportedAccountParams{
				{
					WalletID:  walletID,
					Scope:     db.KeyScopeBIP0084,
					Name:      "first",
					PublicKey: []byte(pub.String()),
				},
				{
					WalletID:  walletID,
					Scope:     tc.scope,
					Name:      tc.other,
					PublicKey: []byte(pub.String()),
				},
			} {
				go func() {
					<-start

					_, err := store.CreateImportedAccount(ctx, params)
					results <- err
				}()
			}

			// Act: release both competing writes before collecting outcomes.
			close(start)

			firstErr, secondErr := <-results, <-results

			// Assert: one account wins; the loser creates no row or child.
			if firstErr != nil {
				firstErr, secondErr = secondErr, firstErr
			}

			require.NoError(t, firstErr)
			require.ErrorIs(t, secondErr, tc.want)

			var accounts, secrets, addresses, next int

			err = store.DB().QueryRowContext(ctx, `
				SELECT (SELECT count(*) FROM accounts),
				       (SELECT count(*) FROM account_secrets),
				       (SELECT count(*) FROM addresses),
				       (SELECT sum(next_account_number) FROM key_scopes)
			`).Scan(&accounts, &secrets, &addresses, &next)
			require.NoError(t, err)
			require.Equal(t, 1, accounts)
			require.Zero(t, secrets)
			require.Zero(t, addresses)
			require.Zero(t, next)
		})
	}
}
