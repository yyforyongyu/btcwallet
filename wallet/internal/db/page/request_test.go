package page

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRequestSize verifies that Size normalizes the raw size field: zero
// maps to DefaultPageSize and values above MaxPageSize are clamped.
func TestRequestSize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		size     uint32
		wantSize uint32
	}{
		{
			name:     "zero defaults to DefaultPageSize",
			size:     0,
			wantSize: DefaultPageSize,
		},
		{
			name:     "minimum in range",
			size:     1,
			wantSize: 1,
		},
		{
			name:     "exactly MaxPageSize passes through",
			size:     MaxPageSize,
			wantSize: MaxPageSize,
		},
		{
			name:     "over MaxPageSize clamped to MaxPageSize",
			size:     uint32(MaxPageSize) + 1,
			wantSize: MaxPageSize,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			request := Request[uint32]{}.WithSize(tc.size)
			require.Equal(t, tc.wantSize, request.Size())
		})
	}
}

// TestQueryLimit verifies that QueryLimit returns Size in deferred mode and
// Size+1 in early-exhaustion mode, including at MaxPageSize.
func TestQueryLimit(t *testing.T) {
	t.Parallel()

	t.Run("non-early-exhaustion uses normalized size", func(t *testing.T) {
		t.Parallel()

		r := Request[uint32]{}.WithSize(25)
		require.Equal(t, r.Size(), r.QueryLimit())
	})

	t.Run("early-exhaustion uses size plus one", func(t *testing.T) {
		t.Parallel()

		r := Request[uint32]{}.WithSize(25).WithEarlyExhaustion()
		require.Equal(t, r.Size()+1, r.QueryLimit())
	})

	t.Run("early-exhaustion at max page size", func(t *testing.T) {
		t.Parallel()

		r := Request[uint32]{}.
			WithSize(MaxPageSize).
			WithEarlyExhaustion()
		require.Equal(t, uint32(MaxPageSize)+1, r.QueryLimit())
	})
}

// TestRequestChaining verifies that chaining With* calls produces the
// expected size and cursor on the resulting Request.
func TestRequestChaining(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		request       Request[uint32]
		wantSize      uint32
		wantCursor    uint32
		wantHasCursor bool
	}{
		{
			name:          "cursor nil by default",
			request:       Request[uint32]{},
			wantSize:      DefaultPageSize,
			wantHasCursor: false,
		},
		{
			name: "cursor set without size",
			request: Request[uint32]{}.
				WithCursor(42),
			wantSize:      DefaultPageSize,
			wantCursor:    42,
			wantHasCursor: true,
		},
		{
			name: "size and cursor set together",
			request: Request[uint32]{}.
				WithSize(50).
				WithCursor(99),
			wantSize:      50,
			wantCursor:    99,
			wantHasCursor: true,
		},
		{
			name: "cursor overwrites previous cursor",
			request: Request[uint32]{}.
				WithCursor(1).
				WithCursor(2),
			wantSize:      DefaultPageSize,
			wantCursor:    2,
			wantHasCursor: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.wantSize, tc.request.Size())

			if !tc.wantHasCursor {
				require.Nil(t, tc.request.Cursor())

				return
			}

			require.NotNil(t, tc.request.Cursor())
			require.Equal(t, tc.wantCursor, *tc.request.Cursor())
		})
	}
}

// TestRequestCursorMode verifies that EarlyExhaustion defaults to false and
// that WithEarlyExhaustion flips it without mutating the original request.
func TestRequestCursorMode(t *testing.T) {
	t.Parallel()

	t.Run("default is deferred exhaustion", func(t *testing.T) {
		t.Parallel()

		r := Request[uint32]{}
		require.False(t, r.EarlyExhaustion())
	})

	t.Run("WithEarlyExhaustion sets early mode", func(t *testing.T) {
		t.Parallel()

		r := Request[uint32]{}.WithEarlyExhaustion()
		require.True(t, r.EarlyExhaustion())
	})

	t.Run("WithEarlyExhaustion keeps size+cursor",
		func(t *testing.T) {
			t.Parallel()

			r := Request[uint32]{}.
				WithSize(50).
				WithCursor(42).
				WithEarlyExhaustion()
			require.Equal(t, uint32(50), r.Size())
			require.NotNil(t, r.Cursor())
			require.Equal(t, uint32(42), *r.Cursor())
			require.True(t, r.EarlyExhaustion())
		})

	t.Run("immutability: WithEarlyExhaustion does not mutate original",
		func(t *testing.T) {
			t.Parallel()

			original := Request[uint32]{}.WithSize(10).WithCursor(7)
			early := original.WithEarlyExhaustion()
			require.False(t, original.EarlyExhaustion())
			require.True(t, early.EarlyExhaustion())
			require.Equal(t, uint32(10), original.Size())
			require.NotNil(t, original.Cursor())
			require.Equal(t, uint32(7), *original.Cursor())
		})
}

// TestRequestWithSizeImmutability verifies that WithSize returns a new
// Request and does not modify the original.
func TestRequestWithSizeImmutability(t *testing.T) {
	t.Parallel()

	original := Request[uint32]{}.
		WithSize(10).
		WithCursor(7)
	updated := original.WithSize(20)

	require.Equal(t, uint32(10), original.Size())
	require.NotNil(t, original.Cursor())
	require.Equal(t, uint32(7), *original.Cursor())

	require.Equal(t, uint32(20), updated.Size())
	require.NotNil(t, updated.Cursor())
	require.Equal(t, uint32(7), *updated.Cursor())
}

// TestRequestWithCursorImmutability verifies that WithCursor returns a new
// Request and does not modify the original.
func TestRequestWithCursorImmutability(t *testing.T) {
	t.Parallel()

	original := Request[uint32]{}.
		WithSize(10).
		WithCursor(7)
	updated := original.WithCursor(9)

	require.Equal(t, uint32(10), original.Size())
	require.NotNil(t, original.Cursor())
	require.Equal(t, uint32(7), *original.Cursor())

	require.Equal(t, uint32(10), updated.Size())
	require.NotNil(t, updated.Cursor())
	require.Equal(t, uint32(9), *updated.Cursor())
}

// TestBuildResult verifies BuildResult assembles the correct Result in both
// deferred and early-exhaustion modes, including trimming and HasMore logic.
func TestBuildResult(t *testing.T) {
	t.Parallel()

	toCursor := func(item int) int { return item }

	testCases := []struct {
		name        string
		items       []int
		size        uint32
		earlyMode   bool
		wantItems   []int
		wantHasMore bool
		wantCursor  *int
	}{
		{
			name:        "empty slice returns empty result",
			items:       []int{},
			size:        100,
			earlyMode:   true,
			wantItems:   []int{},
			wantHasMore: false,
			wantCursor:  nil,
		},
		{
			name:        "deferred: non-empty sets HasMore and LastCursor",
			items:       []int{1, 2, 3},
			size:        100,
			earlyMode:   false,
			wantItems:   []int{1, 2, 3},
			wantHasMore: true,
			wantCursor:  func() *int { v := 3; return &v }(),
		},
		{
			name:        "deferred: single item",
			items:       []int{7},
			size:        100,
			earlyMode:   false,
			wantItems:   []int{7},
			wantHasMore: true,
			wantCursor:  func() *int { v := 7; return &v }(),
		},
		{
			name:        "early: len < size sets HasMore false",
			items:       []int{1, 2},
			size:        5,
			earlyMode:   true,
			wantItems:   []int{1, 2},
			wantHasMore: false,
			wantCursor:  func() *int { v := 2; return &v }(),
		},
		{
			name:        "early: len == size sets HasMore false",
			items:       []int{1, 2},
			size:        2,
			earlyMode:   true,
			wantItems:   []int{1, 2},
			wantHasMore: false,
			wantCursor:  func() *int { v := 2; return &v }(),
		},
		{
			name:        "early: len > size trims and sets HasMore true",
			items:       []int{1, 2, 3},
			size:        2,
			earlyMode:   true,
			wantItems:   []int{1, 2},
			wantHasMore: true,
			wantCursor:  func() *int { v := 2; return &v }(),
		},
		{
			name:        "early: empty slice returns empty result",
			items:       []int{},
			size:        5,
			earlyMode:   true,
			wantItems:   []int{},
			wantHasMore: false,
			wantCursor:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var req Request[int]

			req = req.WithSize(tc.size)
			if tc.earlyMode {
				req = req.WithEarlyExhaustion()
			}

			result := BuildResult(req, tc.items, toCursor)

			require.Equal(t, tc.wantItems, result.Items)
			require.Equal(t, tc.wantHasMore, result.HasMore)
			require.Equal(t, tc.wantCursor, result.LastCursor)
		})
	}
}
