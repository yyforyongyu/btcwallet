package kvdb

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

var errTestAccountNotFound = errors.New("test account not found")

// TestGetAddressDetailsSuccess verifies that kvdb.Store adapts legacy address
// details into the db-native address metadata view used by the wallet.
func TestGetAddressDetailsSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)

	addr, pkScript := newTestAddressScript(t)
	addrStore := &testLegacyAddrStore{
		chainParams: &chaincfg.RegressionNetParams,
		detailsByAddr: map[string]testLegacyAddressDetails{
			addr.String(): {
				spendable: true,
				account:   "default",
				addrType:  waddrmgr.WitnessPubKey,
			},
		},
	}

	store := NewStore(dbConn, nil, addrStore)

	spendable, account, addrType, err := store.GetAddressDetails(
		t.Context(), db.GetAddressDetailsQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.True(t, spendable)
	require.Equal(t, "default", account)
	require.Equal(t, db.WitnessPubKey, addrType)
}

type testLegacyAddressDetails struct {
	spendable bool
	account   string
	addrType  waddrmgr.AddressType
}

type testLegacyAddrStore struct {
	chainParams   *chaincfg.Params
	currentHeight int32
	detailsByAddr map[string]testLegacyAddressDetails
	accountByAddr map[string]uint32
}

func (s *testLegacyAddrStore) ChainParams() *chaincfg.Params {
	return s.chainParams
}

func (s *testLegacyAddrStore) SyncedTo() waddrmgr.BlockStamp {
	return waddrmgr.BlockStamp{Height: s.currentHeight}
}

func (s *testLegacyAddrStore) AddressDetails(_ walletdb.ReadBucket,
	addr btcutil.Address) (bool, string, waddrmgr.AddressType) {

	details, ok := s.detailsByAddr[addr.String()]
	if !ok {
		return false, legacyUnknownAccountName, 0
	}

	return details.spendable, details.account, details.addrType
}

func (s *testLegacyAddrStore) AddrAccount(_ walletdb.ReadBucket,
	addr btcutil.Address) (waddrmgr.AccountStore, uint32, error) {

	account, ok := s.accountByAddr[addr.String()]
	if !ok {
		return nil, 0, errTestAccountNotFound
	}

	return nil, account, nil
}

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
