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
	duplicateInputTx := testRegularMsgTx()
	duplicateInputTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: duplicateInputTx.TxIn[0].PreviousOutPoint,
		Sequence:         wire.MaxTxInSequenceNum,
	})

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
				Tx:     duplicateInputTx,
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

// TestBuildTxInfo verifies the shared row-to-domain mapper for TxInfo values.
//
// Scenario:
// - One normalized SQL row is converted into the public TxInfo shape.
// Setup:
// - Build serialized transaction bytes plus one confirmed block fixture.
// Action:
// - Convert the valid input row with buildTxInfo.
// Assertions:
// - Valid rows preserve hashes, labels, block data, and UTC timestamps.
func TestBuildTxInfo(t *testing.T) {
	t.Parallel()

	// Arrange: Build one valid normalized transaction row.
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

	// Act: Convert the normalized row into the public TxInfo shape.
	info, err := buildTxInfo(
		hash[:], rawTx, time.Unix(600, 0).In(time.FixedZone("X", 3600)),
		block, string(TxStatusPublished), "note",
	)

	// Assert: The public TxInfo view preserves the stored metadata.
	require.NoError(t, err)
	require.Equal(t, hash, info.Hash)
	require.Equal(t, rawTx, info.SerializedTx)
	require.Equal(t, TxStatusPublished, info.Status)
	require.Equal(t, "note", info.Label)
	require.Equal(t, time.UTC, info.Received.Location())
	require.Equal(t, block, info.Block)
}

// TestBuildTxInfoInvalidHash verifies that buildTxInfo rejects malformed
// transaction hashes.
//
// Scenario:
// - One normalized SQL row carries invalid transaction-hash bytes.
// Setup:
// - Build one valid serialized transaction payload.
// Action:
// - Convert the malformed row with buildTxInfo.
// Assertions:
// - The helper returns an error instead of building a partial TxInfo.
func TestBuildTxInfoInvalidHash(t *testing.T) {
	t.Parallel()

	// Arrange: Build one valid serialized transaction payload.
	tx := testRegularMsgTx()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	// Act: Convert a row carrying malformed transaction-hash bytes.
	_, err = buildTxInfo([]byte{1, 2, 3}, rawTx, time.Now(), nil, "pending", "")

	// Assert: The malformed hash is rejected.
	require.Error(t, err)
}

// TestBuildTxInfoInvalidStatus verifies that buildTxInfo rejects unknown stored
// status strings.
//
// Scenario:
// - One normalized SQL row carries an unsupported transaction status.
// Setup:
// - Build one valid serialized transaction payload and hash.
// Action:
// - Convert the malformed row with buildTxInfo.
// Assertions:
// - The helper returns errInvalidTxStatus.
func TestBuildTxInfoInvalidStatus(t *testing.T) {
	t.Parallel()

	// Arrange: Build one valid serialized transaction payload and hash.
	tx := testRegularMsgTx()
	hash := tx.TxHash()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	// Act: Convert a row carrying an unknown transaction status.
	_, err = buildTxInfo(hash[:], rawTx, time.Now(), nil, "bogus", "")

	// Assert: Unknown statuses are rejected.
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
