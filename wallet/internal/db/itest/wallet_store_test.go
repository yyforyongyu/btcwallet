//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/stretchr/testify/require"
)

// TestCreateWallet verifies that CreateWallet correctly creates a wallet
// and returns its information.
func TestCreateWallet(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	params := CreateWalletParamsFixture("test-wallet")
	info, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)
	require.NotNil(t, info)

	require.Equal(t, info.ID, uint32(1), "first wallet ID should be 1")
	require.Equal(t, params.Name, info.Name)
	require.Equal(t, params.IsImported, info.IsImported)
	require.Equal(t, params.ManagerVersion, info.ManagerVersion)
	require.Equal(t, params.IsWatchOnly, info.IsWatchOnly)

	require.Nil(t, info.SyncedTo)
	require.Nil(t, info.BirthdayBlock)
	require.True(t, info.Birthday.IsZero())
}

// TestCreateWallet_WithBirthday checks that CreateWallet correctly sets the
// wallet's birthday timestamp.
func TestCreateWallet_WithBirthday(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("birthday-wallet")
	birthday := time.Now().UTC().Add(-30 * 24 * time.Hour)
	params.Birthday = birthday

	info, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)
	require.NotNil(t, info)

	require.Equal(t, birthday.Unix(), info.Birthday.Unix())
	require.Nil(t, info.BirthdayBlock)
}

// TestCreateWallet_DuplicateName verifies that creating a wallet with a
// duplicate name fails with an appropriate error.
func TestCreateWallet_DuplicateName(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	params := CreateWalletParamsFixture("duplicate-wallet")

	_, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	// Attempt to create second wallet with same name.
	_, err = store.CreateWallet(t.Context(), params)
	require.Error(t, err, "expected error creating duplicate wallet")

	// We still do not normalize this error across database backends,
	// and each engine returns its own message. Because of that,
	// we only check for the shared parts of the message here.
	require.ErrorContains(t, err, "wallets")
	require.ErrorContains(t, err, "name")
	require.ErrorContains(t, err, "constraint")
}

// TestCreateWallet_Variants tests different wallet types.
func TestCreateWallet_Variants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params func(string) db.CreateWalletParams
	}{
		{
			name:   "imported wallet",
			params: CreateImportedWalletParams,
		},
		{
			name:   "watch-only wallet",
			params: CreateWatchOnlyWalletParams,
		},
		{
			name:   "standard wallet",
			params: CreateWalletParamsFixture,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			params := tc.params(tc.name)
			store := NewTestStore(t)

			info, err := store.CreateWallet(t.Context(), params)
			require.NoError(t, err)
			require.NotNil(t, info)
			require.Equal(t, params.IsImported, info.IsImported)
			require.Equal(t, params.IsWatchOnly, info.IsWatchOnly)
		})
	}
}

// TestGetWallet verifies that GetWallet retrieves a wallet by name.
func TestGetWallet(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("get-test-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), params.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
}

// TestGetWallet_NotFound verifies that GetWallet returns ErrWalletNotFound
// when the wallet doesn't exist.
func TestGetWallet_NotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	_, err := store.GetWallet(t.Context(), "non-existent-wallet")
	require.Error(t, err)
	require.ErrorIs(t, err, db.ErrWalletNotFound)
}

// TestListWallets verifies that ListWallets returns one page of wallets and
// handles empty results without error.
func TestListWallets(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	pageResult, err := store.ListWallets(t.Context(), db.ListWalletsQuery{
		Page: page.Request[uint32]{Limit: 10},
	})
	require.NoError(t, err)
	require.Empty(t, pageResult.Items)
	require.False(t, pageResult.HasNext)

	names := []string{"wallet-1", "wallet-2", "wallet-3"}
	for _, name := range names {
		_, err := store.CreateWallet(
			t.Context(), CreateWalletParamsFixture(name),
		)
		require.NoError(t, err)
	}

	pageResult, err = store.ListWallets(t.Context(), db.ListWalletsQuery{
		Page: page.Request[uint32]{Limit: 10},
	})
	require.NoError(t, err)
	require.Len(t, pageResult.Items, 3)
	require.False(t, pageResult.HasNext)

	gotNames := make([]string, len(pageResult.Items))
	for i, wallet := range pageResult.Items {
		gotNames[i] = wallet.Name
	}
	require.ElementsMatch(t, names, gotNames)
}

// TestListWalletsPagination verifies cursor-based pagination over wallets.
func TestListWalletsPagination(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	names := []string{"wallet-1", "wallet-2", "wallet-3", "wallet-4", "wallet-5"}
	for _, name := range names {
		_, err := store.CreateWallet(
			t.Context(), CreateWalletParamsFixture(name),
		)
		require.NoError(t, err)
	}

	query := db.ListWalletsQuery{Page: page.Request[uint32]{Limit: 2}}

	page1, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page1.Items, 2)
	require.True(t, page1.HasNext)
	require.Equal(t, page1.Items[1].ID, page1.Next)

	query.Page = query.Page.WithAfter(page1.Next)
	page2, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page2.Items, 2)
	require.True(t, page2.HasNext)
	require.Equal(t, page2.Items[1].ID, page2.Next)

	query.Page = query.Page.WithAfter(page2.Next)
	page3, err := store.ListWallets(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page3.Items, 1)
	require.False(t, page3.HasNext)
	require.Equal(t, names[4], page3.Items[0].Name)

	wallets := flattenWalletPages([]page.Result[db.WalletInfo, uint32]{
		page1, page2, page3,
	})
	require.Len(t, wallets, len(names))
	for i, wallet := range wallets {
		require.Equal(t, names[i], wallet.Name)
	}
}

// TestIterWallets verifies that IterWallets yields the same items as manual
// page traversal.
func TestIterWallets(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	for _, name := range []string{"wallet-1", "wallet-2", "wallet-3", "wallet-4"} {
		_, err := store.CreateWallet(
			t.Context(), CreateWalletParamsFixture(name),
		)
		require.NoError(t, err)
	}

	query := db.ListWalletsQuery{Page: page.Request[uint32]{Limit: 2}}
	expected := flattenWalletPages(collectWalletPages(t, store, query))

	var got []db.WalletInfo
	for wallet, err := range store.IterWallets(t.Context(), query) {
		require.NoError(t, err)
		got = append(got, wallet)
	}

	require.Equal(t, expected, got)
}

// TestListWalletsPagedFromCursor verifies that a wallet page can resume from a
// previously returned cursor.
func TestListWalletsPagedFromCursor(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	created := make([]*db.WalletInfo, 0, 4)
	for _, name := range []string{"wallet-1", "wallet-2", "wallet-3", "wallet-4"} {
		wallet, err := store.CreateWallet(
			t.Context(), CreateWalletParamsFixture(name),
		)
		require.NoError(t, err)
		created = append(created, wallet)
	}

	pageResult, err := store.ListWallets(t.Context(), db.ListWalletsQuery{
		Page: page.Request[uint32]{Limit: 2}.WithAfter(created[1].ID),
	})
	require.NoError(t, err)
	require.Len(t, pageResult.Items, 2)
	require.Equal(t, created[2].ID, pageResult.Items[0].ID)
	require.Equal(t, created[3].ID, pageResult.Items[1].ID)
	require.False(t, pageResult.HasNext)
}

// TestListWalletsPagedWithSyncMetadata verifies that paginated wallet listings
// include sync metadata.
func TestListWalletsPagedWithSyncMetadata(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()

	birthday1 := time.Now().UTC().Add(-48 * time.Hour)
	birthday2 := time.Now().UTC().Add(-24 * time.Hour)

	params1 := CreateWalletParamsFixture("wallet-sync-1")
	params1.Birthday = birthday1
	wallet1, err := store.CreateWallet(t.Context(), params1)
	require.NoError(t, err)

	params2 := CreateWalletParamsFixture("wallet-sync-2")
	params2.Birthday = birthday2
	wallet2, err := store.CreateWallet(t.Context(), params2)
	require.NoError(t, err)

	block1 := CreateBlockFixture(t, queries, 100)
	block2 := CreateBlockFixture(t, queries, 101)

	err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID:      wallet1.ID,
		SyncedTo:      &block2,
		BirthdayBlock: &block1,
	})
	require.NoError(t, err)

	err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID:      wallet2.ID,
		SyncedTo:      &block2,
		BirthdayBlock: &block1,
	})
	require.NoError(t, err)

	page1, err := store.ListWallets(t.Context(), db.ListWalletsQuery{
		Page: page.Request[uint32]{Limit: 1},
	})
	require.NoError(t, err)
	require.Len(t, page1.Items, 1)
	require.NotNil(t, page1.Items[0].SyncedTo)
	require.NotNil(t, page1.Items[0].BirthdayBlock)
	require.False(t, page1.Items[0].Birthday.IsZero())
	require.True(t, page1.HasNext)

	page2, err := store.ListWallets(t.Context(), db.ListWalletsQuery{
		Page: page.Request[uint32]{Limit: 1}.WithAfter(page1.Next),
	})
	require.NoError(t, err)
	require.Len(t, page2.Items, 1)
	require.NotNil(t, page2.Items[0].SyncedTo)
	require.NotNil(t, page2.Items[0].BirthdayBlock)
	require.False(t, page2.Items[0].Birthday.IsZero())
	require.False(t, page2.HasNext)
}

// TestListWalletsCursorEdges verifies stale and zero cursors produce
// deterministic page results.
func TestListWalletsCursorEdges(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	names := []string{"wallet-1", "wallet-2", "wallet-3"}
	for _, name := range names {
		_, err := store.CreateWallet(
			t.Context(), CreateWalletParamsFixture(name),
		)
		require.NoError(t, err)
	}

	stalePage, err := store.ListWallets(t.Context(), db.ListWalletsQuery{
		Page: page.Request[uint32]{Limit: 2}.WithAfter(^uint32(0)),
	})
	require.NoError(t, err)
	require.Empty(t, stalePage.Items)
	require.False(t, stalePage.HasNext)

	zeroPage, err := store.ListWallets(t.Context(), db.ListWalletsQuery{
		Page: page.Request[uint32]{Limit: 2}.WithAfter(0),
	})
	require.NoError(t, err)
	require.Len(t, zeroPage.Items, 2)
	require.Equal(t, names[0], zeroPage.Items[0].Name)
	require.True(t, zeroPage.HasNext)
	require.Equal(t, zeroPage.Items[1].ID, zeroPage.Next)
}

// collectWalletPages collects paginated wallet results until HasNext is false.
func collectWalletPages(t *testing.T, store db.WalletStore,
	query db.ListWalletsQuery) []page.Result[db.WalletInfo, uint32] {
	t.Helper()

	pages := make([]page.Result[db.WalletInfo, uint32], 0)
	for {
		pageResult, err := store.ListWallets(t.Context(), query)
		require.NoError(t, err)
		pages = append(pages, pageResult)

		if !pageResult.HasNext {
			return pages
		}

		query.Page = query.Page.WithAfter(pageResult.Next)
	}
}

// flattenWalletPages flattens paginated wallet results into a single slice.
func flattenWalletPages(
	pages []page.Result[db.WalletInfo, uint32]) []db.WalletInfo {

	count := 0
	for i := range pages {
		count += len(pages[i].Items)
	}

	wallets := make([]db.WalletInfo, 0, count)
	for i := range pages {
		wallets = append(wallets, pages[i].Items...)
	}

	return wallets
}

// TestUpdateWallet_SyncedTo checks that updating the wallet's synced-to block
// works correctly.
func TestUpdateWallet_SyncedTo(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()

	params := CreateWalletParamsFixture("update-sync-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	block := CreateBlockFixture(t, queries, 100)

	updateParams := db.UpdateWalletParams{
		WalletID: created.ID,
		SyncedTo: &block,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved.SyncedTo)
	require.Equal(t, block.Height, retrieved.SyncedTo.Height)

	// Assert fields that were not updated remain unchanged.
	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
	require.Nil(t, retrieved.BirthdayBlock)
}

// TestUpdateWallet_BirthdayBlock checks that updating the wallet's birthday
// block works correctly.
func TestUpdateWallet_BirthdayBlock(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()

	params := CreateWalletParamsFixture("update-birthday-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	// Initially, BirthdayBlock should be nil.
	require.Nil(t, created.BirthdayBlock)

	block := CreateBlockFixture(t, queries, 50)

	updateParams := db.UpdateWalletParams{
		WalletID:      created.ID,
		BirthdayBlock: &block,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved.BirthdayBlock)
	require.Equal(t, block.Height, retrieved.BirthdayBlock.Height)
	require.Equal(t, block.Hash, retrieved.BirthdayBlock.Hash)
	require.Equal(t, block.Timestamp.Unix(),
		retrieved.BirthdayBlock.Timestamp.Unix())

	// Assert fields that were not updated remain unchanged.
	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
	require.Nil(t, retrieved.SyncedTo)
}

// TestUpdateWallet_Birthday checks that updating the wallet's birthday
// timestamp works correctly.
func TestUpdateWallet_Birthday(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("birthday-timestamp-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	// Set birthday timestamp without setting birthday block.
	birthdayTime := time.Now().UTC().Add(-30 * 24 * time.Hour)
	updateParams := db.UpdateWalletParams{
		WalletID: created.ID,
		Birthday: &birthdayTime,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.Equal(t, birthdayTime.Unix(), retrieved.Birthday.Unix())

	// Assert fields that were not updated remain unchanged.
	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
	require.Nil(t, retrieved.BirthdayBlock)
	require.Nil(t, retrieved.SyncedTo)
}

// TestUpdateWallet_NotFound verifies that updating a non-existent wallet fails.
func TestUpdateWallet_NotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	updateParams := db.UpdateWalletParams{
		WalletID: 99999, // Non-existent ID.
	}

	err := store.UpdateWallet(t.Context(), updateParams)
	require.Error(t, err)
	require.ErrorIs(t, err, db.ErrWalletNotFound)
}

// TestGetEncryptedHDSeed verifies retrieving the encrypted HD seed.
func TestGetEncryptedHDSeed(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("seed-wallet")
	expectedSeed := params.EncryptedMasterPrivKey

	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.NoError(t, err)
	require.Equal(t, expectedSeed, seed)
}

// TestGetEncryptedHDSeed_WatchOnly verifies that watch-only wallets
// have no encrypted seed.
func TestGetEncryptedHDSeed_WatchOnly(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWatchOnlyWalletParams("watch-only-seed")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.Nil(t, seed, "watch-only wallets should not have HD seed")
	require.ErrorIs(t, err, db.ErrSecretNotFound)
}

// TestUpdateWalletSecrets checks that updating the wallet secrets works
// correctly.
func TestUpdateWalletSecrets(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("secrets-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	newSecrets := db.UpdateWalletSecretsParams{
		WalletID:                 created.ID,
		MasterPrivParams:         RandomBytes(16),
		EncryptedCryptoPrivKey:   RandomBytes(32),
		EncryptedCryptoScriptKey: RandomBytes(32),
		EncryptedMasterHdPrivKey: RandomBytes(32),
	}

	err = store.UpdateWalletSecrets(t.Context(), newSecrets)
	require.NoError(t, err)

	seed, err := store.GetEncryptedHDSeed(t.Context(), created.ID)
	require.NoError(t, err)
	require.Equal(t, newSecrets.EncryptedMasterHdPrivKey, seed)
}

// TestUpdateWallet_AutoBlockInsertion verifies that UpdateWallet automatically
// inserts blocks when updating SyncedTo or BirthdayBlock.
func TestUpdateWallet_AutoBlockInsertion(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("auto-block-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	// Create a block WITHOUT pre-inserting it into the blocks table.
	block := db.Block{
		Height:    uint32(100),
		Hash:      RandomHash(),
		Timestamp: time.Now().UTC(),
	}

	// Update wallet with SyncedTo - should automatically insert the block.
	updateParams := db.UpdateWalletParams{
		WalletID: created.ID,
		SyncedTo: &block,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	// Verify the wallet was updated.
	retrieved, err := store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved.SyncedTo)
	require.Equal(t, block.Height, retrieved.SyncedTo.Height)
	require.Equal(t, block.Hash, retrieved.SyncedTo.Hash)

	// Update again with the same block - should be idempotent.
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err, "updating with same block should be idempotent")

	// Create another block for BirthdayBlock.
	birthdayBlock := db.Block{
		Height:    uint32(50),
		Hash:      RandomHash(),
		Timestamp: time.Now().UTC().Add(-time.Hour),
	}

	// Update wallet with BirthdayBlock - should automatically insert it.
	updateParams = db.UpdateWalletParams{
		WalletID:      created.ID,
		BirthdayBlock: &birthdayBlock,
	}
	err = store.UpdateWallet(t.Context(), updateParams)
	require.NoError(t, err)

	// Verify both blocks are set.
	retrieved, err = store.GetWallet(t.Context(), created.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved.SyncedTo)
	require.NotNil(t, retrieved.BirthdayBlock)
	require.Equal(t, block.Height, retrieved.SyncedTo.Height)
	require.Equal(t, birthdayBlock.Height, retrieved.BirthdayBlock.Height)
}
