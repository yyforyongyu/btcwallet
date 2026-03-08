package db

import (
	"bytes"
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestSerializeDeserializeMsgTx verifies the common transaction serialization
// helpers.
//
// Scenario:
// - One regular transaction is serialized and then decoded again.
// Setup:
// - Build one representative regular transaction fixture.
// Action:
// - Serialize the transaction and deserialize the resulting bytes.
// Assertions:
// - The decoded transaction re-serializes to the exact original bytes.
func TestSerializeDeserializeMsgTx(t *testing.T) {
	t.Parallel()

	tx := testRegularMsgTx()

	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	decoded, err := deserializeMsgTx(rawTx)
	require.NoError(t, err)

	var got bytes.Buffer

	err = decoded.Serialize(&got)
	require.NoError(t, err)

	require.Equal(t, rawTx, got.Bytes())
}

// TestParseTxStatus verifies the shared stored-status parser.
//
// Scenario:
// - The database returns both valid and invalid status strings.
// Setup:
// - Define one table-driven set of stored status values and expectations.
// Action:
// - Parse each stored string through the shared helper.
// Assertions:
// - Known values map to the public TxStatus enum.
// - Unknown values fail with errInvalidTxStatus.
func TestParseTxStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  string
		want    TxStatus
		wantErr error
	}{
		{name: "pending", status: "pending", want: TxStatusPending},
		{name: "published", status: "published", want: TxStatusPublished},
		{name: "replaced", status: "replaced", want: TxStatusReplaced},
		{name: "failed", status: "failed", want: TxStatusFailed},
		{name: "orphaned", status: "orphaned", want: TxStatusOrphaned},
		{name: "invalid", status: "bogus", wantErr: errInvalidTxStatus},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseTxStatus(tc.status)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestValidateCreateTxParams verifies the shared CreateTx preflight checks.
//
// Scenario:
// - Callers submit valid and invalid transaction-create requests.
// Setup:
// - Define one table-driven set of parameter combinations and expected errors.
// Action:
// - Validate each parameter set before any backend transaction opens.
// Assertions:
// - Invalid combinations fail with the expected sentinel error.
// - Supported pending and confirmed requests are accepted.
func TestValidateCreateTxParams(t *testing.T) {
	t.Parallel()

	confirmedBlock := &Block{Height: 100, Timestamp: time.Unix(123, 0)}

	tests := []struct {
		name    string
		params  CreateTxParams
		wantErr error
	}{
		{
			name:    "nil transaction",
			params:  CreateTxParams{},
			wantErr: errNilTransaction,
		},
		{
			name: "coinbase requires block",
			params: CreateTxParams{
				Tx:     testCoinbaseMsgTx(),
				Status: TxStatusPublished,
			},
			wantErr: errCoinbaseRequiresBlock,
		},
		{
			name: "confirmed transaction must be published",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Block:  confirmedBlock,
				Status: TxStatusPending,
			},
			wantErr: errConfirmedRequiresPublished,
		},
		{
			name: "orphaned status rejected on create",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Status: TxStatusOrphaned,
			},
			wantErr: errCreateTxOrphanedStatus,
		},
		{
			name: "failed status rejected on create",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Status: TxStatusFailed,
			},
			wantErr: errCreateTxTerminalStatus,
		},
		{
			name: "replaced status rejected on create",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Status: TxStatusReplaced,
			},
			wantErr: errCreateTxTerminalStatus,
		},
		{
			name: "credit index out of range",
			params: CreateTxParams{
				Tx: testRegularMsgTx(),
				Credits: []CreditData{{
					Index: 2,
				}},
				Status: TxStatusPending,
			},
			wantErr: errCreditIndexOutOfRange,
		},
		{
			name: "duplicate credit index",
			params: CreateTxParams{
				Tx: testRegularMsgTx(),
				Credits: []CreditData{
					{Index: 0},
					{Index: 0},
				},
				Status: TxStatusPending,
			},
			wantErr: errDuplicateCreditIndex,
		},
		{
			name: "valid pending unmined transaction",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Status: TxStatusPending,
				Credits: []CreditData{{
					Index: 0,
				}},
			},
		},
		{
			name: "valid published mined coinbase",
			params: CreateTxParams{
				Tx:     testCoinbaseMsgTx(),
				Block:  confirmedBlock,
				Status: TxStatusPublished,
				Credits: []CreditData{{
					Index: 0,
				}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateCreateTxParams(tc.params)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestBuildTxInfo verifies the shared row-to-domain mapper for TxInfo values.
//
// Scenario:
// - One normalized SQL row is converted into the public TxInfo shape.
// Setup:
// - Build serialized transaction bytes plus one confirmed block fixture.
// Action:
// - Convert valid and invalid input rows with buildTxInfo.
// Assertions:
// - Valid rows preserve hashes, labels, block data, and UTC timestamps.
// - Invalid hashes and unknown statuses fail loudly.
func TestBuildTxInfo(t *testing.T) {
	t.Parallel()

	tx := testRegularMsgTx()
	hash := tx.TxHash()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	blockHash := chainhash.Hash{1, 2, 3}
	block := &Block{
		Hash:      blockHash,
		Height:    77,
		Timestamp: time.Unix(500, 0),
	}

	info, err := buildTxInfo(
		hash[:], rawTx, time.Unix(600, 0).In(time.FixedZone("X", 3600)),
		block, string(TxStatusPublished), "note",
	)
	require.NoError(t, err)
	require.Equal(t, hash, info.Hash)
	require.Equal(t, rawTx, info.SerializedTx)
	require.Equal(t, TxStatusPublished, info.Status)
	require.Equal(t, "note", info.Label)
	require.Equal(t, time.UTC, info.Received.Location())
	require.Equal(t, block, info.Block)

	_, err = buildTxInfo([]byte{1, 2, 3}, rawTx, time.Now(), nil, "pending", "")
	require.Error(t, err)

	_, err = buildTxInfo(hash[:], rawTx, time.Now(), nil, "bogus", "")
	require.ErrorIs(t, err, errInvalidTxStatus)
}

// testRegularMsgTx builds one regular transaction fixture for shared mapper and
// serialization tests.
func testRegularMsgTx() *wire.MsgTx {
	tx := wire.NewMsgTx(wire.TxVersion)

	prevHash := chainhash.Hash{9}
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  prevHash,
			Index: 1,
		},
		Sequence: wire.MaxTxInSequenceNum,
	})
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})
	tx.AddTxOut(&wire.TxOut{Value: 2000, PkScript: []byte{0x51, 0x51}})

	return tx
}

// testCoinbaseMsgTx builds one minimal coinbase fixture transaction for shared
// mapper and serialization tests.
func testCoinbaseMsgTx() *wire.MsgTx {
	tx := wire.NewMsgTx(wire.TxVersion)

	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: math.MaxUint32},
		SignatureScript:  []byte{0x01, 0x02},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	tx.AddTxOut(&wire.TxOut{Value: 50, PkScript: []byte{0x51}})

	return tx
}
