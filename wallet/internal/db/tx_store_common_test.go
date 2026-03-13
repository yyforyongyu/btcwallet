package db

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

var (
	errTestRollbackList   = errors.New("list failed")
	errTestRollbackClear  = errors.New("clear failed")
	errTestRollbackUpdate = errors.New("update failed")
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

func TestDeserializeMsgTxInvalidRaw(t *testing.T) {
	t.Parallel()

	_, err := deserializeMsgTx([]byte{1, 2, 3})
	require.ErrorContains(t, err, "deserialize transaction")
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
		{name: "negative", status: -1, wantErr: errInvalidTxStatus},
		{name: "overflow", status: 256, wantErr: errInvalidTxStatus},
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
			name: "invalid status",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Status: TxStatus(9),
			},
			wantErr: errInvalidTxStatus,
		},
		{
			name: "credit index out of range",
			params: CreateTxParams{
				Tx:      testRegularMsgTx(),
				Credits: map[uint32]btcutil.Address{2: nil},
				Status:  TxStatusPending,
			},
			wantErr: errCreditIndexOutOfRange,
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
				Tx:      testRegularMsgTx(),
				Status:  TxStatusPending,
				Credits: map[uint32]btcutil.Address{0: nil},
			},
		},
		{
			name: "valid published mined coinbase",
			params: CreateTxParams{
				Tx:      testCoinbaseMsgTx(),
				Block:   confirmedBlock,
				Status:  TxStatusPublished,
				Credits: map[uint32]btcutil.Address{0: nil},
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

type rollbackTestRow struct {
	id    int64
	hash  []byte
	rawTx []byte
}

type rollbackClearParams struct {
	walletID     int64
	descendantID int64
}

type rollbackUpdateParams struct {
	walletID      int64
	descendantIDs []int64
}

func TestApplyRollbackDescendantInvalidationNoDescendants(t *testing.T) {
	t.Parallel()

	rootHash := chainhash.Hash{1}
	unrelatedHash := chainhash.Hash{9}
	rowsByWallet := map[int64][]rollbackTestRow{
		7: {rollbackTestRowFixture(
			t, 10, unrelatedHash,
			testMsgTxSpendingOutPoints(wire.OutPoint{Hash: chainhash.Hash{8}}),
		)},
	}

	var (
		clearCalls  []rollbackClearParams
		updateCalls []rollbackUpdateParams
	)

	err := applyRollbackDescendantInvalidation(
		t.Context(),
		map[uint32]map[chainhash.Hash]struct{}{
			7: {rootHash: {}},
		},
		func(_ context.Context, walletID int64) ([]rollbackTestRow, error) {
			return rowsByWallet[walletID], nil
		},
		func(row rollbackTestRow) (int64, []byte, []byte) {
			return row.id, row.hash, row.rawTx
		},
		func(_ context.Context, params rollbackClearParams) (int64, error) {
			clearCalls = append(clearCalls, params)
			return 1, nil
		},
		func(walletID int64, descendantID int64) rollbackClearParams {
			return rollbackClearParams{
				walletID:     walletID,
				descendantID: descendantID,
			}
		},
		func(_ context.Context, params rollbackUpdateParams) (int64, error) {
			updateCalls = append(updateCalls, params)
			return int64(len(params.descendantIDs)), nil
		},
		func(walletID int64, descendantIDs []int64) rollbackUpdateParams {
			return rollbackUpdateParams{
				walletID:      walletID,
				descendantIDs: append([]int64(nil), descendantIDs...),
			}
		},
	)
	require.NoError(t, err)
	require.Empty(t, clearCalls)
	require.Empty(t, updateCalls)
}

func TestApplyRollbackDescendantInvalidationMultiWalletIsolation(t *testing.T) {
	t.Parallel()

	rootHashOne := chainhash.Hash{1}
	rootHashTwo := chainhash.Hash{2}
	childHashOne := chainhash.Hash{3}
	grandchildHashOne := chainhash.Hash{4}
	childHashTwo := chainhash.Hash{5}
	rowsByWallet := map[int64][]rollbackTestRow{
		1: {
			rollbackTestRowFixture(
				t, 11, childHashOne,
				testMsgTxSpendingOutPoints(
					wire.OutPoint{Hash: rootHashOne, Index: 0},
				),
			),
			rollbackTestRowFixture(
				t, 12, grandchildHashOne,
				testMsgTxSpendingOutPoints(
					wire.OutPoint{Hash: childHashOne, Index: 0},
				),
			),
		},
		2: {
			rollbackTestRowFixture(
				t, 21, childHashTwo,
				testMsgTxSpendingOutPoints(
					wire.OutPoint{Hash: rootHashTwo, Index: 0},
				),
			),
		},
	}

	var (
		clearCalls  []rollbackClearParams
		updateCalls []rollbackUpdateParams
	)

	err := applyRollbackDescendantInvalidation(
		t.Context(),
		map[uint32]map[chainhash.Hash]struct{}{
			1: {rootHashOne: {}},
			2: {rootHashTwo: {}},
		},
		func(_ context.Context, walletID int64) ([]rollbackTestRow, error) {
			return rowsByWallet[walletID], nil
		},
		func(row rollbackTestRow) (int64, []byte, []byte) {
			return row.id, row.hash, row.rawTx
		},
		func(_ context.Context, params rollbackClearParams) (int64, error) {
			clearCalls = append(clearCalls, params)
			return 1, nil
		},
		func(walletID int64, descendantID int64) rollbackClearParams {
			return rollbackClearParams{
				walletID:     walletID,
				descendantID: descendantID,
			}
		},
		func(_ context.Context, params rollbackUpdateParams) (int64, error) {
			updateCalls = append(updateCalls, params)
			return int64(len(params.descendantIDs)), nil
		},
		func(walletID int64, descendantIDs []int64) rollbackUpdateParams {
			return rollbackUpdateParams{
				walletID:      walletID,
				descendantIDs: append([]int64(nil), descendantIDs...),
			}
		},
	)
	require.NoError(t, err)
	require.ElementsMatch(t, []rollbackClearParams{
		{walletID: 1, descendantID: 11},
		{walletID: 1, descendantID: 12},
		{walletID: 2, descendantID: 21},
	}, clearCalls)
	require.ElementsMatch(t, []rollbackUpdateParams{
		{walletID: 1, descendantIDs: []int64{11, 12}},
		{walletID: 2, descendantIDs: []int64{21}},
	}, updateCalls)
}

func TestApplyRollbackDescendantInvalidationListError(t *testing.T) {
	t.Parallel()

	err := applyRollbackDescendantInvalidation(
		t.Context(),
		map[uint32]map[chainhash.Hash]struct{}{
			7: {chainhash.Hash{1}: {}},
		},
		func(context.Context, int64) ([]rollbackTestRow, error) {
			return nil, errTestRollbackList
		},
		func(row rollbackTestRow) (int64, []byte, []byte) {
			return row.id, row.hash, row.rawTx
		},
		func(context.Context, rollbackClearParams) (int64, error) {
			return 0, nil
		},
		func(walletID int64, descendantID int64) rollbackClearParams {
			return rollbackClearParams{
				walletID:     walletID,
				descendantID: descendantID,
			}
		},
		func(context.Context, rollbackUpdateParams) (int64, error) {
			return 0, nil
		},
		func(walletID int64, descendantIDs []int64) rollbackUpdateParams {
			return rollbackUpdateParams{
				walletID:      walletID,
				descendantIDs: descendantIDs,
			}
		},
	)
	require.ErrorContains(t, err, "list live rollback descendants for wallet 7")
	require.ErrorIs(t, err, errTestRollbackList)
}

func TestApplyRollbackDescendantInvalidationDecodeHashError(t *testing.T) {
	t.Parallel()

	err := applyRollbackDescendantInvalidation(
		t.Context(),
		map[uint32]map[chainhash.Hash]struct{}{
			7: {chainhash.Hash{1}: {}},
		},
		func(context.Context, int64) ([]rollbackTestRow, error) {
			return []rollbackTestRow{{
				id:    10,
				hash:  []byte{1, 2, 3},
				rawTx: mustSerializeTestTx(t, testRegularMsgTx()),
			}}, nil
		},
		func(row rollbackTestRow) (int64, []byte, []byte) {
			return row.id, row.hash, row.rawTx
		},
		func(context.Context, rollbackClearParams) (int64, error) {
			return 0, nil
		},
		func(walletID int64, descendantID int64) rollbackClearParams {
			return rollbackClearParams{
				walletID:     walletID,
				descendantID: descendantID,
			}
		},
		func(context.Context, rollbackUpdateParams) (int64, error) {
			return 0, nil
		},
		func(walletID int64, descendantIDs []int64) rollbackUpdateParams {
			return rollbackUpdateParams{
				walletID:      walletID,
				descendantIDs: descendantIDs,
			}
		},
	)
	require.ErrorContains(t, err, "decode live transaction 10")
	require.ErrorContains(t, err, "transaction hash")
}

func TestApplyRollbackDescendantInvalidationDecodeTxError(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{2}

	err := applyRollbackDescendantInvalidation(
		t.Context(),
		map[uint32]map[chainhash.Hash]struct{}{
			7: {chainhash.Hash{1}: {}},
		},
		func(context.Context, int64) ([]rollbackTestRow, error) {
			return []rollbackTestRow{{
				id:    10,
				hash:  hash[:],
				rawTx: []byte{1, 2, 3},
			}}, nil
		},
		func(row rollbackTestRow) (int64, []byte, []byte) {
			return row.id, row.hash, row.rawTx
		},
		func(context.Context, rollbackClearParams) (int64, error) {
			return 0, nil
		},
		func(walletID int64, descendantID int64) rollbackClearParams {
			return rollbackClearParams{
				walletID:     walletID,
				descendantID: descendantID,
			}
		},
		func(context.Context, rollbackUpdateParams) (int64, error) {
			return 0, nil
		},
		func(walletID int64, descendantIDs []int64) rollbackUpdateParams {
			return rollbackUpdateParams{
				walletID:      walletID,
				descendantIDs: descendantIDs,
			}
		},
	)
	require.ErrorContains(t, err, "decode live transaction 10")
	require.ErrorContains(t, err, "deserialize transaction")
}

func TestApplyRollbackDescendantInvalidationClearError(t *testing.T) {
	t.Parallel()

	rootHash := chainhash.Hash{1}
	childHash := chainhash.Hash{2}

	err := applyRollbackDescendantInvalidation(
		t.Context(),
		map[uint32]map[chainhash.Hash]struct{}{
			7: {rootHash: {}},
		},
		func(context.Context, int64) ([]rollbackTestRow, error) {
			return []rollbackTestRow{rollbackTestRowFixture(
				t, 10, childHash,
				testMsgTxSpendingOutPoints(
					wire.OutPoint{Hash: rootHash, Index: 0},
				),
			)}, nil
		},
		func(row rollbackTestRow) (int64, []byte, []byte) {
			return row.id, row.hash, row.rawTx
		},
		func(context.Context, rollbackClearParams) (int64, error) {
			return 0, errTestRollbackClear
		},
		func(walletID int64, descendantID int64) rollbackClearParams {
			return rollbackClearParams{
				walletID:     walletID,
				descendantID: descendantID,
			}
		},
		func(context.Context, rollbackUpdateParams) (int64, error) {
			return 0, nil
		},
		func(walletID int64, descendantIDs []int64) rollbackUpdateParams {
			return rollbackUpdateParams{
				walletID:      walletID,
				descendantIDs: descendantIDs,
			}
		},
	)
	require.ErrorContains(
		t, err, "clear rollback descendant spends for wallet 7",
	)
	require.ErrorIs(t, err, errTestRollbackClear)
}

func TestApplyRollbackDescendantInvalidationUpdateError(t *testing.T) {
	t.Parallel()

	rootHash := chainhash.Hash{1}
	childHash := chainhash.Hash{2}

	err := applyRollbackDescendantInvalidation(
		t.Context(),
		map[uint32]map[chainhash.Hash]struct{}{
			7: {rootHash: {}},
		},
		func(context.Context, int64) ([]rollbackTestRow, error) {
			return []rollbackTestRow{rollbackTestRowFixture(
				t, 10, childHash,
				testMsgTxSpendingOutPoints(
					wire.OutPoint{Hash: rootHash, Index: 0},
				),
			)}, nil
		},
		func(row rollbackTestRow) (int64, []byte, []byte) {
			return row.id, row.hash, row.rawTx
		},
		func(context.Context, rollbackClearParams) (int64, error) {
			return 1, nil
		},
		func(walletID int64, descendantID int64) rollbackClearParams {
			return rollbackClearParams{
				walletID:     walletID,
				descendantID: descendantID,
			}
		},
		func(context.Context, rollbackUpdateParams) (int64, error) {
			return 0, errTestRollbackUpdate
		},
		func(walletID int64, descendantIDs []int64) rollbackUpdateParams {
			return rollbackUpdateParams{
				walletID:      walletID,
				descendantIDs: descendantIDs,
			}
		},
	)
	require.ErrorContains(
		t, err, "mark rollback descendants failed for wallet 7",
	)
	require.ErrorIs(t, err, errTestRollbackUpdate)
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

func TestIsLiveUnconfirmedStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status TxStatus
		want   bool
	}{
		{status: TxStatusPending, want: true},
		{status: TxStatusPublished, want: true},
		{status: TxStatusReplaced, want: false},
		{status: TxStatusFailed, want: false},
		{status: TxStatusOrphaned, want: false},
		{status: TxStatus(99), want: false},
	}

	for _, test := range tests {
		require.Equal(t, test.want, isLiveUnconfirmedStatus(test.status))
	}
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

func mustSerializeTestTx(t *testing.T, tx *wire.MsgTx) []byte {
	t.Helper()

	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	return rawTx
}

func rollbackTestRowFixture(t *testing.T, id int64, hash chainhash.Hash,
	tx *wire.MsgTx) rollbackTestRow {

	t.Helper()

	return rollbackTestRow{
		id:    id,
		hash:  hash[:],
		rawTx: mustSerializeTestTx(t, tx),
	}
}

func testMsgTxSpendingOutPoints(outPoints ...wire.OutPoint) *wire.MsgTx {
	tx := wire.NewMsgTx(wire.TxVersion)

	for _, outPoint := range outPoints {
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: outPoint})
	}

	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})

	return tx
}
