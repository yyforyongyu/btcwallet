package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseTxStatusNegativeValue verifies that parseTxStatus rejects negative
// stored values before they can map into the public TxStatus enum.
func TestParseTxStatusNegativeValue(t *testing.T) {
	t.Parallel()

	_, err := parseTxStatus(-1)
	require.ErrorIs(t, err, ErrInvalidStatus)
}

// TestIsUnminedStatus verifies the delete-specific classification for each
// transaction status.
func TestIsUnminedStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status TxStatus
		want   bool
	}{
		{name: "pending", status: TxStatusPending, want: true},
		{name: "published", status: TxStatusPublished, want: true},
		{name: "replaced", status: TxStatusReplaced, want: false},
		{name: "failed", status: TxStatusFailed, want: false},
		{name: "orphaned", status: TxStatusOrphaned, want: false},
		{name: "unknown", status: TxStatus(99), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, test.want, isUnminedStatus(test.status))
		})
	}
}
