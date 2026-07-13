package keyvault

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/stretchr/testify/require"
)

// testGenesisRootKey builds a deterministic spendable HD root key for genesis
// tests.
func testGenesisRootKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	seed := []byte("0123456789abcdef0123456789abcdef")
	hdRootKey, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	return hdRootKey
}

// TestCreateWalletSecretsSpendableRoundtrip verifies that spendable secrets
// produced by CreateWalletSecrets decrypt back to the same crypto keys and HD
// root key under the correct passphrase — the parity guarantee that a SQL
// wallet derives the same keys as the legacy backend for a given seed.
func TestCreateWalletSecretsSpendableRoundtrip(t *testing.T) {
	t.Parallel()

	passphrase := []byte("correct horse battery staple")
	hdRootKey := testGenesisRootKey(t)

	secrets, err := CreateWalletSecrets(passphrase, hdRootKey, false)
	require.NoError(t, err)

	// A spendable wallet persists all four secret fields.
	require.NotEmpty(t, secrets.MasterPrivParams)
	require.NotEmpty(t, secrets.EncryptedCryptoPrivKey)
	require.NotEmpty(t, secrets.EncryptedCryptoScriptKey)
	require.NotEmpty(t, secrets.EncryptedMasterHdPrivKey)

	state, err := decryptWalletSecrets(secrets, passphrase, false)
	require.NoError(t, err)

	defer state.zero()

	// The decrypted HD root key must round-trip exactly.
	require.NotNil(t, state.hdRootKey)
	require.Equal(t, hdRootKey.String(), state.hdRootKey.String())

	// The runtime crypto keys must be populated.
	require.NotEqual(t, snacl.CryptoKey{}, state.cryptoKeyPrivate)
	require.NotEqual(t, snacl.CryptoKey{}, state.cryptoKeyScript)
}

// TestCreateWalletSecretsWatchOnlyRoundtrip verifies that watch-only secrets
// carry only the script crypto key and decrypt without private material.
func TestCreateWalletSecretsWatchOnlyRoundtrip(t *testing.T) {
	t.Parallel()

	passphrase := []byte("correct horse battery staple")

	secrets, err := CreateWalletSecrets(passphrase, nil, true)
	require.NoError(t, err)

	// Watch-only wallets hold no private material.
	require.NotEmpty(t, secrets.MasterPrivParams)
	require.NotEmpty(t, secrets.EncryptedCryptoScriptKey)
	require.Empty(t, secrets.EncryptedCryptoPrivKey)
	require.Empty(t, secrets.EncryptedMasterHdPrivKey)

	state, err := decryptWalletSecrets(secrets, passphrase, true)
	require.NoError(t, err)

	defer state.zero()

	require.Nil(t, state.hdRootKey)
	require.NotEqual(t, snacl.CryptoKey{}, state.cryptoKeyScript)
	require.Equal(t, snacl.CryptoKey{}, state.cryptoKeyPrivate)
}

// TestCreateWalletSecretsWrongPassphrase verifies that decrypting genesis
// secrets with the wrong passphrase fails with ErrInvalidPassphrase.
func TestCreateWalletSecretsWrongPassphrase(t *testing.T) {
	t.Parallel()

	secrets, err := CreateWalletSecrets(
		[]byte("correct horse battery staple"), testGenesisRootKey(t), false,
	)
	require.NoError(t, err)

	_, err = decryptWalletSecrets(secrets, []byte("wrong passphrase"), false)
	require.ErrorIs(t, err, ErrInvalidPassphrase)
}

// TestCreateWalletSecretsInputGuards verifies that CreateWalletSecrets rejects
// invalid spendable inputs before deriving secret material, while watch-only
// wallets keep accepting a neutered xpub and an empty passphrase.
func TestCreateWalletSecretsInputGuards(t *testing.T) {
	t.Parallel()

	passphrase := []byte("correct horse battery staple")

	tests := []struct {
		name       string
		passphrase []byte
		rootKey    func(t *testing.T) *hdkeychain.ExtendedKey
		watchOnly  bool
		wantErr    error
	}{
		{
			name:       "spendable private key and passphrase",
			passphrase: passphrase,
			rootKey:    testGenesisRootKey,
			watchOnly:  false,
			wantErr:    nil,
		},
		{
			name:       "spendable nil root key",
			passphrase: passphrase,
			rootKey: func(*testing.T) *hdkeychain.ExtendedKey {
				return nil
			},
			watchOnly: false,
			wantErr:   errUnexpectedState,
		},
		{
			name:       "spendable neutered root key",
			passphrase: passphrase,
			rootKey: func(t *testing.T) *hdkeychain.ExtendedKey {
				t.Helper()

				neutered, err := testGenesisRootKey(t).Neuter()
				require.NoError(t, err)

				return neutered
			},
			watchOnly: false,
			wantErr:   errRootKeyNotPrivate,
		},
		{
			name:       "spendable empty passphrase",
			passphrase: nil,
			rootKey:    testGenesisRootKey,
			watchOnly:  false,
			wantErr:    errEmptyPassphrase,
		},
		{
			name:       "watch-only neutered key empty passphrase",
			passphrase: nil,
			rootKey: func(t *testing.T) *hdkeychain.ExtendedKey {
				t.Helper()

				neutered, err := testGenesisRootKey(t).Neuter()
				require.NoError(t, err)

				return neutered
			},
			watchOnly: true,
			wantErr:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			secrets, err := CreateWalletSecrets(
				tc.passphrase, tc.rootKey(t), tc.watchOnly,
			)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, secrets)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, secrets)
		})
	}
}
