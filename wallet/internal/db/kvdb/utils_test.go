package kvdb

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

const defaultDBTimeout = 10 * time.Second

var errTestAccountNotFound = errors.New("test account not found")

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
		_, err := tx.CreateTopLevelBucket(waddrmgr.NamespaceKey)
		return err
	})
	require.NoError(t, err)
}

// testAddrStore is a narrow legacy address-manager test double.
type testAddrStore struct {
	chainParams   *chaincfg.Params
	currentHeight int32
	accountByAddr map[string]uint32
	addressByAddr map[string]waddrmgr.ManagedAddress
	usedAddrs     map[string]bool
}

// ActiveScopedKeyManagers returns no scoped managers for this test double.
func (s *testAddrStore) ActiveScopedKeyManagers() []waddrmgr.AccountStore {
	return nil
}

// Address returns the managed address registered for this test double.
func (s *testAddrStore) Address(_ walletdb.ReadBucket,
	addr btcutil.Address) (waddrmgr.ManagedAddress, error) {

	managedAddr, ok := s.addressByAddr[addr.String()]
	if ok {
		return managedAddr, nil
	}

	return nil, errTestAccountNotFound
}

// AddrAccount returns the test account number for the requested address.
func (s *testAddrStore) AddrAccount(_ walletdb.ReadBucket,
	addr btcutil.Address) (waddrmgr.AccountStore, uint32, error) {

	account, ok := s.accountByAddr[addr.String()]
	if !ok {
		return nil, 0, errTestAccountNotFound
	}

	return nil, account, nil
}

// Birthday returns the zero birthday for this test double.
func (s *testAddrStore) Birthday() time.Time {
	return time.Time{}
}

// BirthdayBlock returns no verified birthday block for this test double.
func (s *testAddrStore) BirthdayBlock(
	_ walletdb.ReadBucket) (waddrmgr.BlockStamp, bool, error) {

	return waddrmgr.BlockStamp{}, false, nil
}

// BlockHash fails block-hash lookup for this test double.
func (s *testAddrStore) BlockHash(_ walletdb.ReadBucket,
	_ int32) (*chainhash.Hash, error) {

	return nil, errTestAccountNotFound
}

// ChangePassphrase accepts passphrase updates for this test double.
func (s *testAddrStore) ChangePassphrase(_ walletdb.ReadWriteBucket,
	_, _ []byte, _ bool, _ *waddrmgr.ScryptOptions) error {

	return nil
}

// ChainParams returns the chain parameters for this test double.
func (s *testAddrStore) ChainParams() *chaincfg.Params {
	return s.chainParams
}

// Decrypt returns the input unchanged for tests that do not inspect secrets.
func (s *testAddrStore) Decrypt(_ waddrmgr.CryptoKeyType,
	in []byte) ([]byte, error) {

	return in, nil
}

// MarkUsed records address-used updates for this test double.
func (s *testAddrStore) MarkUsed(_ walletdb.ReadWriteBucket,
	addr btcutil.Address) error {

	if s.usedAddrs != nil {
		s.usedAddrs[addr.String()] = true
	}

	return nil
}

// NewScopedKeyManager fails scoped manager creation for this test double.
func (s *testAddrStore) NewScopedKeyManager(
	_ walletdb.ReadWriteBucket, _ waddrmgr.KeyScope,
	_ waddrmgr.ScopeAddrSchema) (waddrmgr.AccountStore, error) {

	return nil, errTestAccountNotFound
}

// FetchScopedKeyManager fails scoped manager lookup for this test double.
func (s *testAddrStore) FetchScopedKeyManager(
	_ waddrmgr.KeyScope) (waddrmgr.AccountStore, error) {

	return nil, errTestAccountNotFound
}

// SetBirthday accepts birthday updates for this test double.
func (s *testAddrStore) SetBirthday(_ walletdb.ReadWriteBucket,
	_ time.Time) error {

	return nil
}

// SetBirthdayBlock accepts birthday-block updates for this test double.
func (s *testAddrStore) SetBirthdayBlock(_ walletdb.ReadWriteBucket,
	_ waddrmgr.BlockStamp, _ bool) error {

	return nil
}

// SetSyncedTo records the sync height for this test double.
func (s *testAddrStore) SetSyncedTo(_ walletdb.ReadWriteBucket,
	bs *waddrmgr.BlockStamp) error {

	if bs != nil {
		s.currentHeight = bs.Height
	}

	return nil
}

// SyncedTo returns the current test sync height.
func (s *testAddrStore) SyncedTo() waddrmgr.BlockStamp {
	return waddrmgr.BlockStamp{Height: s.currentHeight}
}

// Unlock accepts private-key unlocks for this test double.
func (s *testAddrStore) Unlock(_ walletdb.ReadBucket,
	_ []byte) error {

	return nil
}

// AddressDetails is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testAddrStore) AddressDetails(_ walletdb.ReadBucket,
	_ btcutil.Address) (bool, string, waddrmgr.AddressType) {

	return false, "", 0
}

// ConvertToWatchingOnly is a no-op stub for waddrmgr.AddrStore.
func (s *testAddrStore) ConvertToWatchingOnly(
	_ walletdb.ReadWriteBucket) error {

	return nil
}

// Close is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testAddrStore) Close() {}

// EncryptedMasterHDPriv is a no-op stub for waddrmgr.AddrStore.
func (s *testAddrStore) EncryptedMasterHDPriv(
	_ walletdb.ReadBucket) ([]byte, error) {

	return nil, nil
}

// MasterHDPubKey is a no-op stub for the waddrmgr.AddrStore interface.
// Tests that exercise derived-account fingerprint resolution should override
// this on a per-test basis with a valid serialized extended public key.
func (s *testAddrStore) MasterHDPubKey(
	_ walletdb.ReadBucket) ([]byte, error) {

	return nil, nil
}

// ForEachAccountAddress is a no-op stub for waddrmgr.AddrStore.
func (s *testAddrStore) ForEachAccountAddress(_ walletdb.ReadBucket,
	_ uint32, _ func(waddrmgr.ManagedAddress) error) error {

	return nil
}

// ForEachActiveAddress is a no-op stub for waddrmgr.AddrStore.
func (s *testAddrStore) ForEachActiveAddress(_ walletdb.ReadBucket,
	_ func(btcutil.Address) error) error {

	return nil
}

// ForEachRelevantActiveAddress is a no-op stub for waddrmgr.AddrStore.
func (s *testAddrStore) ForEachRelevantActiveAddress(
	_ walletdb.ReadBucket, _ func(btcutil.Address) error) error {

	return nil
}

// IsLocked is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testAddrStore) IsLocked() bool { return false }

// IsWatchOnlyAccount is a no-op stub for waddrmgr.AddrStore.
func (s *testAddrStore) IsWatchOnlyAccount(_ walletdb.ReadBucket,
	_ waddrmgr.KeyScope, _ uint32) (bool, error) {

	return false, nil
}

// Lock is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testAddrStore) Lock() error { return nil }

// LookupAccount is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testAddrStore) LookupAccount(_ walletdb.ReadBucket,
	_ string) (waddrmgr.KeyScope, uint32, error) {

	return waddrmgr.KeyScope{}, 0, nil
}

// WatchOnly is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testAddrStore) WatchOnly() bool { return false }

// newTestAddressScript returns a test address and its payment script.
func newTestAddressScript(t *testing.T) (btcutil.Address, []byte) {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	addr, err := btcutil.NewAddressPubKey(
		privKey.PubKey().SerializeCompressed(), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return addr, pkScript
}

// testManagedAddress is a minimal managed address used by kvdb store tests.
type testManagedAddress struct {
	addr     btcutil.Address
	internal bool
}

// InternalAccount returns the default account for this test address.
func (a *testManagedAddress) InternalAccount() uint32 { return 0 }

// Address returns the backing bitcoin address.
func (a *testManagedAddress) Address() btcutil.Address { return a.addr }

// AddrHash returns no address hash for this test double.
func (a *testManagedAddress) AddrHash() []byte { return nil }

// Imported reports that this test address is derived.
func (a *testManagedAddress) Imported() bool { return false }

// Internal returns whether this test address is an internal address.
func (a *testManagedAddress) Internal() bool { return a.internal }

// Compressed reports that this test address uses compressed keys.
func (a *testManagedAddress) Compressed() bool { return true }

// Used reports that this test address is unused.
func (a *testManagedAddress) Used(_ walletdb.ReadBucket) bool { return false }

// AddrType returns the default witness-pubkey type for this test address.
func (a *testManagedAddress) AddrType() waddrmgr.AddressType {
	return waddrmgr.WitnessPubKey
}
