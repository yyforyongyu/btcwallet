package page

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// errTest is a sentinel error used across page package tests.
var errTest = errors.New("test error")

// TestIterTraversal verifies that Iter walks all pages in order.
func TestIterTraversal(t *testing.T) {
	t.Parallel()

	pages := []Result[int, int]{
		{Items: []int{1, 2}, Next: 2, HasNext: true},
		{Items: []int{3, 4}, Next: 4, HasNext: true},
		{Items: []int{5}},
	}

	var (
		fetchCalls int
		cursors    []int
		items      []int
	)

	fetch := func(_ context.Context, query int) (Result[int, int], error) {
		require.Less(t, fetchCalls, len(pages))
		if fetchCalls > 0 {
			require.Equal(t, cursors[len(cursors)-1], query)
		}

		result := pages[fetchCalls]
		fetchCalls++

		return result, nil
	}

	withAfter := func(_ int, cursor int) int {
		cursors = append(cursors, cursor)

		return cursor
	}

	for item, err := range Iter(t.Context(), 0, fetch, withAfter) {
		require.NoError(t, err)
		items = append(items, item)
	}

	require.Equal(t, []int{1, 2, 3, 4, 5}, items)
	require.Equal(t, 3, fetchCalls)
	require.Equal(t, []int{2, 4}, cursors)
}

// TestIterFetchError verifies that Iter yields a terminal fetch error.
func TestIterFetchError(t *testing.T) {
	t.Parallel()

	fetch := func(_ context.Context, _ int) (Result[int, int], error) {
		return Result[int, int]{}, errTest
	}

	withAfter := func(query int, _ int) int {
		return query
	}

	for item, err := range Iter(t.Context(), 0, fetch, withAfter) {
		require.Zero(t, item)
		require.ErrorIs(t, err, errTest)

		return
	}

	t.Fatal("expected terminal error")
}

// TestIterContextCancellationBeforeFetch verifies that Iter stops before the
// first fetch when the context is already canceled.
func TestIterContextCancellationBeforeFetch(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	fetch := func(_ context.Context, _ int) (Result[int, int], error) {
		t.Fatal("unexpected fetch")

		return Result[int, int]{}, nil
	}

	withAfter := func(query int, _ int) int {
		return query
	}

	for item, err := range Iter(ctx, 0, fetch, withAfter) {
		require.Zero(t, item)
		require.ErrorIs(t, err, context.Canceled)

		return
	}

	t.Fatal("expected terminal cancellation error")
}

// TestIterContextCancellationMidPage verifies that Iter stops promptly when the
// context is canceled during item emission.
func TestIterContextCancellationMidPage(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	fetch := func(_ context.Context, _ int) (Result[int, int], error) {
		return Result[int, int]{
			Items:   []int{1, 2, 3},
			HasNext: false,
		}, nil
	}

	withAfter := func(query int, _ int) int {
		return query
	}

	var items []int
	for item, err := range Iter(ctx, 0, fetch, withAfter) {
		if err != nil {
			require.Zero(t, item)
			require.ErrorIs(t, err, context.Canceled)

			break
		}

		items = append(items, item)
		if len(items) == 1 {
			cancel()
		}
	}

	require.Equal(t, []int{1}, items)
}

// TestIterConsumerBreak verifies that Iter stops without fetching another page
// when the consumer breaks early.
func TestIterConsumerBreak(t *testing.T) {
	t.Parallel()

	pages := []Result[int, int]{
		{Items: []int{1, 2}, Next: 2, HasNext: true},
		{Items: []int{3, 4}},
	}

	var fetchCalls int
	fetch := func(_ context.Context, query int) (Result[int, int], error) {
		_ = query
		result := pages[fetchCalls]
		fetchCalls++

		return result, nil
	}

	withAfter := func(_ int, cursor int) int {
		return cursor
	}

	var items []int
	for item, err := range Iter(t.Context(), 0, fetch, withAfter) {
		require.NoError(t, err)
		items = append(items, item)
		if len(items) == 1 {
			break
		}
	}

	require.Equal(t, []int{1}, items)
	require.Equal(t, 1, fetchCalls)
}
