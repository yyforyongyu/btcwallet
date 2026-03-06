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

// TestSerializeDeserializeMsgTx verifies that the common serialization helpers
// preserve transaction bytes across a round trip.
//
// Scenario:
// - A transaction is serialized for storage and then decoded again.
// Setup:
// - Build one minimal non-coinbase transaction fixture.
// Action:
// - Serialize the transaction, deserialize it, and serialize the decoded copy.
// Assertions:
// - The final serialized bytes match the original payload exactly.
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

// TestParseTxStatus verifies that stored numeric values map back to the public
// TxStatus enum and that unknown values fail loudly.
//
// Scenario:
// - SQL rows carry both valid and invalid transaction status codes.
// Setup:
// - Define one table of known statuses plus one unknown input.
// Action:
// - Parse each stored status code.
// Assertions:
// - Known codes map to the expected TxStatus values.
// - Unknown codes fail with errInvalidTxStatus.
func TestParseTxStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  int64
		want    TxStatus
		wantErr error
	}{
		{name: "pending", status: 0, want: TxStatusPending},
		{name: "published", status: 1, want: TxStatusPublished},
		{name: "replaced", status: 2, want: TxStatusReplaced},
		{name: "failed", status: 3, want: TxStatusFailed},
		{name: "orphaned", status: 4, want: TxStatusOrphaned},
		{name: "invalid", status: 9, wantErr: errInvalidTxStatus},
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

// TestValidateCreateTxParams verifies the shared CreateTx invariants that both
// SQL backends rely on before opening a write transaction.
//
// Scenario:
// - Callers submit valid and invalid transaction-create requests.
// Setup:
// - Define one table of parameter combinations and expected outcomes.
// Action:
// - Validate each parameter set before any backend write transaction opens.
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
			name: "duplicate input outpoint",
			params: CreateTxParams{
				Tx: &wire.MsgTx{
					Version: wire.TxVersion,
					TxIn: []*wire.TxIn{
						{
							PreviousOutPoint: wire.OutPoint{
								Hash:  chainhash.Hash{1},
								Index: 0,
							},
						},
						{
							PreviousOutPoint: wire.OutPoint{
								Hash:  chainhash.Hash{1},
								Index: 0,
							},
						},
					},
					TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
				},
				Status: TxStatusPending,
			},
			wantErr: errDuplicateInputOutPoint,
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

// TestBuildTxInfo verifies the shared row-to-domain conversion used by both
// SQL backends when returning a valid TxInfo value.
//
// Scenario:
// - One normalized transaction row is read back from the store.
// Setup:
// - Build a valid serialized transaction, hash, and confirmed block.
// Action:
// - Convert the normalized row into a public TxInfo value.
// Assertions:
// - The persisted wallet metadata is preserved.
func TestBuildTxInfo(t *testing.T) {
	t.Parallel()

	// Scenario: One normalized transaction row is read back from the store.
	// Setup: Build a valid serialized transaction, hash, and confirmed block.
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

	// Act: Build the public TxInfo view from the normalized row fields.
	info, err := buildTxInfo(
		hash[:], rawTx, time.Unix(600, 0).In(time.FixedZone("X", 3600)),
		block, int64(TxStatusPublished), "note",
	)

	// Assert: The helper preserves the persisted wallet metadata.
	require.NoError(t, err)
	require.Equal(t, hash, info.Hash)
	require.Equal(t, rawTx, info.SerializedTx)
	require.Equal(t, TxStatusPublished, info.Status)
	require.Equal(t, "note", info.Label)
	require.Equal(t, time.UTC, info.Received.Location())
	require.Equal(t, block, info.Block)
}

// TestBuildTxInfo_InvalidHash verifies that buildTxInfo rejects malformed hash
// bytes.
//
// Scenario:
// - A normalized transaction row carries malformed hash bytes.
// Setup:
// - Build a valid serialized transaction payload.
// Action:
// - Attempt to convert the malformed row into a public TxInfo value.
// Assertions:
// - The helper returns an error instead of building a partial TxInfo.
func TestBuildTxInfo_InvalidHash(t *testing.T) {
	t.Parallel()

	// Scenario: A normalized row carries invalid transaction-hash bytes.
	// Setup: Build a valid serialized transaction payload.
	tx := testRegularMsgTx()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	// Act: Attempt to build the public TxInfo view.
	_, err = buildTxInfo([]byte{1, 2, 3}, rawTx, time.Now(), nil,
		int64(TxStatusPending), "")

	// Assert: The helper rejects the malformed hash.
	require.Error(t, err)
}

// TestBuildTxInfo_InvalidStatus verifies that buildTxInfo rejects unknown
// status codes.
//
// Scenario:
// - A normalized transaction row carries an unknown status code.
// Setup:
// - Build a valid serialized transaction payload and hash.
// Action:
// - Attempt to convert the row into a public TxInfo value.
// Assertions:
// - The helper returns errInvalidTxStatus.
func TestBuildTxInfo_InvalidStatus(t *testing.T) {
	t.Parallel()

	// Scenario: A normalized row carries an unknown transaction status.
	// Setup: Build a valid serialized transaction payload and hash.
	tx := testRegularMsgTx()
	hash := tx.TxHash()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	// Act: Attempt to build the public TxInfo view.
	_, err = buildTxInfo(hash[:], rawTx, time.Now(), nil, 9, "")

	// Assert: The helper returns the invalid-status sentinel.
	require.ErrorIs(t, err, errInvalidTxStatus)
}

// testRegularMsgTx builds a minimal non-coinbase transaction fixture for the
// shared TxStore helper tests.
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

// testCoinbaseMsgTx builds a minimal coinbase transaction fixture for the
// shared TxStore helper tests.
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
