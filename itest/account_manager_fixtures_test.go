//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/stretchr/testify/require"
)

// canonicalAccountKey returns a serialized account extended key normalized to
// the network's default public HD version.
//
// The version has to be normalized because the two stores publish a *derived*
// account's key under different versions. kvdb reads the key back through
// waddrmgr, which re-exports it with the key scope's HD version
// (cloneKeyWithVersion: BIP84 on testnet becomes vpub), while the SQL stores
// return the bytes the wallet derived from the master key, which keep the
// network's default version (tpub). Normalizing only the version preserves the
// complete extended-key identity across both backends.
//
// This normalization applies to derived accounts only: waddrmgr deliberately
// leaves imported and watch-only account keys as the caller supplied them, so
// the import test compares the serialized key byte for byte.
func canonicalAccountKey(h *bwtest.HarnessTest, key []byte) []byte {
	h.Helper()

	parsed, err := hdkeychain.NewKeyFromString(string(key))
	require.NoError(h, err, "failed to decode account public key")
	normalized, err := parsed.CloneWithVersion(
		h.NetParams().HDPublicKeyID[:],
	)
	require.NoError(h, err, "failed to normalize account public key version")

	return []byte(normalized.String())
}
