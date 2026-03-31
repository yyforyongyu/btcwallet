package kvdb

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

const defaultDBTimeout = 10 * time.Second

var (
	testPubPass  = []byte("public")
	testPrivPass = []byte("private")
)

// newTestDB creates a temporary bdb walletdb for kvdb store tests.
//
// It returns the opened database and a cleanup function that must be called
// after the test completes.
func newTestDB(t *testing.T) (walletdb.DB, func()) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "wallet.db")

	dbConn, err := walletdb.Create(
		"bdb", dbPath, true, defaultDBTimeout, false,
	)
	require.NoError(t, err)

	cleanup := func() {
		_ = dbConn.Close()
	}

	return dbConn, cleanup
}

// newTxStore initializes and opens a wtxmgr store in the test database.
//
// NOTE: The kvdb Store under test expects the walletdb top-level bucket key
// `wtxmgrNamespaceKey` to exist and contain a valid wtxmgr store.
func newTxStore(t *testing.T, dbConn walletdb.DB) *wtxmgr.Store {
	t.Helper()

	var txStore *wtxmgr.Store

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if err != nil {
			return err
		}

		err = wtxmgr.Create(ns)
		if err != nil {
			return err
		}

		txStore, err = wtxmgr.Open(ns, &chaincfg.RegressionNetParams)

		return err
	})
	require.NoError(t, err)

	return txStore
}

// newAddrmgrNamespace creates the top-level waddrmgr bucket expected by kvdb
// address-related tests.
func newAddrmgrNamespace(t *testing.T, dbConn walletdb.DB) {
	t.Helper()

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		_, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		return err
	})
	require.NoError(t, err)
}

// newAddrStore creates and opens a real legacy waddrmgr manager for kvdb
// adapter tests that need address-derivation and import behavior.
func newAddrStore(t *testing.T, dbConn walletdb.DB) *waddrmgr.Manager {
	t.Helper()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	rootKey, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return err
		}

		return waddrmgr.Create(
			ns, rootKey, testPubPass, testPrivPass,
			&chaincfg.RegressionNetParams, nil, time.Unix(1, 0),
		)
	})
	require.NoError(t, err)

	var addrStore *waddrmgr.Manager

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		var err error

		addrStore, err = waddrmgr.Open(
			ns, testPubPass, &chaincfg.RegressionNetParams,
		)

		return err
	})
	require.NoError(t, err)

	t.Cleanup(addrStore.Close)

	return addrStore
}
