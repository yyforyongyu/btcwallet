package wallet

import (
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// BenchmarkListAccountsByScopeAPI benchmarks ListAccountsByScope API and a
// deprecated variant of it using same key scope and identical test data across
// multiple dataset sizes. Test names start with dataset size to group API
// comparisons for benchstat analysis.
func BenchmarkListAccountsByScopeAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
			utxoGrowthPadding, utxoGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.Accounts(scopes[0])
				require.NoError(b, err)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.ListAccountsByScope(
					b.Context(), scopes[0],
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkListAccountsAPI benchmarks ListAccounts API and a deprecated variant
// of it using same key scopes and identical test data across multiple dataset
// sizes. Test names start with dataset size to group API comparisons for
// benchstat analysis.
func BenchmarkListAccountsAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = waddrmgr.DefaultKeyScopes
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
			utxoGrowthPadding, utxoGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := listAccountsDeprecated(bw.Wallet)
				require.NoError(b, err)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.ListAccounts(b.Context())
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkListAccountsByNameAPI benchmarks ListAccountsByName API and a
// deprecated variant of it using same key scopes and identical test data across
// multiple dataset sizes. Test names start with dataset size to group API
// comparisons for benchstat analysis.
func BenchmarkListAccountsByNameAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = waddrmgr.DefaultKeyScopes
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		accountName, _ := generateAccountName(accountGrowth[i], scopes)

		name := fmt.Sprintf("%0*d-Accounts-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
			utxoGrowthPadding, utxoGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := listAccountsByNameDeprecated(
					bw.Wallet, accountName,
				)
				require.NoError(b, err)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.ListAccountsByName(
					b.Context(), accountName,
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkNewAccountAPI benchmarks NewAccount API and NextAccount API using
// identical account creation operations across multiple dataset sizes. Test
// names start with dataset size to group API comparisons for benchstat
// analysis.
func BenchmarkNewAccountAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 10
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			count := 0
			for b.Loop() {
				// Generate a unique account name for each
				// iteration to ensure the idempotent nature of
				// the benchmark.
				accountName := fmt.Sprintf("new-account-%d",
					count)

				_, err := bw.NextAccount(
					scopes[0], accountName,
				)
				require.NoError(b, err)

				count++
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			count := 0
			for b.Loop() {
				// Generate a unique account name for each
				// iteration to ensure the idempotent nature of
				// the benchmark.
				accountName := fmt.Sprintf("new-account-%d",
					count)

				_, err := w.NewAccount(b.Context(), NewAccountParams{
					Scope: scopes[0],
					Name:  accountName,
				})
				require.NoError(b, err)

				count++
			}
		})
	}
}

// BenchmarkGetAccountAPI benchmarks GetAccount API and a deprecated wrapper API
// using identical account lookups across multiple dataset sizes. Test names
// start with dataset size to group API comparisons for benchstat analysis.
func BenchmarkGetAccountAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		accountName, _ := generateAccountName(accountGrowth[i], scopes)

		name := fmt.Sprintf("%0*d-Accounts-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
			utxoGrowthPadding, utxoGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := getAccountDeprecated(
					bw.Wallet, scopes[0], accountName,
				)
				require.NoError(b, err)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.GetAccount(
					b.Context(), scopes[0], accountName,
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkRenameAccountAPI benchmarks RenameAccount API and
// RenameAccountDeprecated API using identical rename operations across multiple
// dataset sizes. Test names start with dataset size to group API comparisons
// for benchstat analysis.
func BenchmarkRenameAccountAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 11
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		accountName, accountNumber := generateAccountName(
			accountGrowth[i], scopes,
		)
		newAccountName := accountName + "-renamed"

		name := fmt.Sprintf("%0*d-Accounts", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			count := 0
			for b.Loop() {
				newAccountName2 := fmt.Sprintf("%s-%d",
					newAccountName, count)

				err := w.RenameAccountDeprecated(
					scopes[0], accountNumber,
					newAccountName2,
				)
				require.NoError(b, err)

				// Rename back to original to keep the benchmark
				// idempotent.
				err = w.RenameAccountDeprecated(
					scopes[0], accountNumber, accountName,
				)
				require.NoError(b, err)

				count++
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			newAccountName := accountName + "-renamed"

			b.ReportAllocs()
			b.ResetTimer()

			count := 0
			for b.Loop() {
				newAccountName2 := fmt.Sprintf("%s-%d",
					newAccountName, count)

				err := w.RenameAccount(
					b.Context(), scopes[0], accountName,
					newAccountName2,
				)
				require.NoError(b, err)

				// Rename back to original to keep the benchmark
				// idempotent.
				err = w.RenameAccount(
					b.Context(), scopes[0], newAccountName2,
					accountName,
				)
				require.NoError(b, err)

				count++
			}
		})
	}
}

// BenchmarkImportAccountAPI benchmarks ImportAccount API and
// ImportAccountDeprecated API using identical account import operations
// across multiple dataset sizes. Test names start with dataset size to group
// API comparisons for benchstat analysis.
func BenchmarkImportAccountAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 10
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		dryRun = false
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		accountKey, masterFingerprint, addrT := generateTestExtendedKey(
			b, accountGrowth[i],
		)
		inputFingerprint := MasterFingerprint(masterFingerprint)

		name := fmt.Sprintf("%0*d-Accounts", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			count := 0
			for b.Loop() {
				// Generate a unique account name for each
				// iteration to ensure the idempotent nature of
				// the benchmark.
				accountName := fmt.Sprintf("import-account-%d",
					count)

				_, err := w.ImportAccountDeprecated(
					accountName, accountKey,
					masterFingerprint, &addrT,
				)
				require.NoError(b, err)

				count++
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			count := 0
			for b.Loop() {
				// Generate a unique account name for each
				// iteration to ensure the idempotent nature of
				// the benchmark.
				accountName := fmt.Sprintf("import-account-%d",
					count)

				_, err := w.ImportAccount(
					b.Context(), ImportAccountParams{
						Name:                 accountName,
						XPub:                 accountKey,
						AddrType:             addrT,
						MasterKeyFingerprint: &inputFingerprint,
					}, dryRun,
				)
				require.NoError(b, err)

				count++
			}
		})
	}
}

// BenchmarkManagerInitialDerivedAccounts compares the public creation batch
// with the cutover's individual family calls using the same locked result.
func BenchmarkManagerInitialDerivedAccounts(b *testing.B) {
	// Arrange: All samples use the same exact family paths. Database/chain
	// fixture setup and teardown are excluded from the measured operation.
	scope := waddrmgr.KeyScope{Purpose: 1017, Coin: 1}
	schema := waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084]

	var accounts []NewAccountParams

	for number := AccountNumber(0); number <= 255; number++ {
		name := fmt.Sprintf("act:%d", number)
		if number == 0 {
			name = waddrmgr.DefaultAccountName
		}

		accounts = append(accounts, NewAccountParams{
			Scope:         scope,
			Name:          name,
			AccountNumber: &number,
			AddrSchema:    &schema,
			NoChainSync:   true,
		})
	}

	tests := []struct {
		name  string
		open  func(testing.TB) *Manager
		batch bool
	}{
		{
			name:  "sqlite/individual",
			open:  testSQLiteManager,
			batch: false,
		},
		{
			name:  "sqlite/initial",
			open:  testSQLiteManager,
			batch: true,
		},
		{
			name:  "kvdb/individual",
			open:  testKVDBManager,
			batch: false,
		},
		{
			name:  "kvdb/initial",
			open:  testKVDBManager,
			batch: true,
		},
	}
	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				b.StopTimer()

				manager := tc.open(b)

				params := CreateWalletParams{
					Name:                   "initial-benchmark",
					Mode:                   ModeImportSeed,
					Seed:                   make([]byte, 32),
					RootKey:                nil,
					PubPassphrase:          []byte("public"),
					PrivatePassphrase:      []byte("private"),
					Birthday:               time.Now(),
					InitialAccounts:        nil,
					InitialDerivedAccounts: nil,
					RecoveryWindow:         nil,
					WatchOnly:              false,
				}
				if tc.batch {
					params.InitialDerivedAccounts = accounts
				}

				b.StartTimer()

				// Act: Measure creation plus family preparation, ending
				// locked in both public API sequences.
				w, err := manager.Create(params)
				require.NoError(b, err)

				if !tc.batch {
					require.NoError(b, w.Unlock(b.Context(), UnlockRequest{
						Passphrase: params.PrivatePassphrase,
						Timeout:    -1,
					}))

					for _, account := range accounts {
						_, err = w.NewAccount(b.Context(), account)
						require.NoError(b, err)
					}

					require.NoError(b, w.Lock(b.Context()))
				}

				b.StopTimer()

				// Assert: Join workers before another sample; existing
				// fixture cleanup owns the single mock verification.
				require.NoError(b, manager.Stop())

				// Loop requires a running timer at its iteration boundary.
				b.StartTimer()
			}
		})
	}
}
