//go:build !js

package kvdb

// Register the filesystem backend only on native targets. The adapter's
// interfaces remain available to RPC clients without linking bbolt on js.
import _ "github.com/btcsuite/btcwallet/walletdb/bdb"
