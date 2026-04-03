package page

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRequestEffectiveLimit verifies that EffectiveLimit normalizes the raw
// request limit.
func TestRequestEffectiveLimit(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		request   Request[uint32]
		wantLimit uint32
	}{
		{
			name:      "zero uses default",
			request:   Request[uint32]{},
			wantLimit: DefaultLimit,
		},
		{
			name:      "within range passes through",
			request:   Request[uint32]{Limit: 25},
			wantLimit: 25,
		},
		{
			name:      "over max clamps",
			request:   Request[uint32]{Limit: MaxLimit + 1},
			wantLimit: MaxLimit,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.wantLimit, tc.request.EffectiveLimit())
		})
	}
}

// TestRequestWithAfter verifies that WithAfter sets the resume cursor without
// mutating the original request.
func TestRequestWithAfter(t *testing.T) {
	t.Parallel()

	original := Request[uint32]{Limit: 10}
	updated := original.WithAfter(42)

	require.Equal(t, uint32(10), original.Limit)
	require.False(t, original.HasAfter)

	require.Equal(t, uint32(10), updated.Limit)
	require.True(t, updated.HasAfter)
	require.Equal(t, uint32(42), updated.After)
}

// TestBuildResult verifies lookahead trimming and next-cursor derivation.
func TestBuildResult(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		items       []int
		limit       uint32
		wantItems   []int
		wantNext    int
		wantHasNext bool
	}{
		{
			name:        "empty page",
			items:       nil,
			limit:       2,
			wantItems:   nil,
			wantHasNext: false,
		},
		{
			name:        "page without lookahead",
			items:       []int{1, 2},
			limit:       2,
			wantItems:   []int{1, 2},
			wantHasNext: false,
		},
		{
			name:        "page with lookahead trims and sets next",
			items:       []int{1, 2, 3},
			limit:       2,
			wantItems:   []int{1, 2},
			wantNext:    2,
			wantHasNext: true,
		},
		{
			name:        "zero limit uses default",
			items:       []int{1, 2, 3},
			limit:       0,
			wantItems:   []int{1, 2, 3},
			wantHasNext: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := BuildResult(tc.items, tc.limit, func(v int) int {
				return v
			})

			require.Equal(t, tc.wantItems, result.Items)
			require.Equal(t, tc.wantHasNext, result.HasNext)
			if tc.wantHasNext {
				require.Equal(t, tc.wantNext, result.Next)
			}
		})
	}
}
