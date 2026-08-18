# bwtest

`bwtest` contains the integration test harness used by `itest`.

## Overview

The harness provides:

- A shared miner (btcd) that produces blocks for all test cases.
- A configurable chain backend under test (`btcd`, `bitcoind`, `neutrino`).
- Per-subtest resources:
  - A fresh `chain.Interface` instance.
  - A fresh wallet database instance.
- Cleanup that keeps tests isolated:
  - Stops wallets created by the test.
  - Requires the miner mempool to be empty on success.

## Logs

Each test run creates a per-run log directory under `itest/test-logs`.

- Backend logs are flattened into `miner.log` and `chain_backend.log`.
- Wallet logs are written per test case as `wallet-<testname>.log`.

## Backends

Chain backends are implemented in separate files:

- `bwtest/btcd.go`
- `bwtest/bitcoind.go`
- `bwtest/neutrino.go`

The `bitcoind` backend uses ZMQ for block/tx notifications.

## Wallet Helpers

`bwtest` owns wallet creation, funding and lock policy so component tests do
not each define their own. `(*HarnessTest).NewWallet` and
`(*HarnessTest).NewManagedWallet` take a `WalletFixture` describing what the
case needs. `NewWallet` returns the wallet with the outpoints funding produced:

```go
func testFoo(t *bwtest.HarnessTest) {
	w, outpoints := t.NewWallet(bwtest.WalletFixture{
		AddrType: waddrmgr.WitnessPubKey,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC},
		Unlocked: true,
	})

	// Now add tests that need a wallet with two spendable coins.
}
```

`WalletFixture` carries the funding address type, funding amounts, whether to
unlock, and whether to leave the wallet unstarted. Its zero value returns a
started, locked wallet. `WatchOnly` creates a rootless `ModeShell` watch-only
wallet.
`InitialAccounts` seeds a watch-only shell wallet; a non-empty slice implies
watch-only even when `WatchOnly` is false, and nil and empty slices are
equivalent. A case that selects funded coins derives its key scope from the
same `AddrType` with `KeyScope()`, so the funded scope has one authority.

`NewManagedWallet` returns the same prepared wallet and funding with a
`ManagedWallet` bundle containing its `Config`, `Manager`, and `Wallet`. Use it
when a component test needs the reload handle, then pass the bundle to
`(*HarnessTest).ReloadWallet`. A successful reload consumes the old generation
and returns a fresh, registered, started, but locked replacement bundle from
the same persistent store.

Tests with custom `CreateWalletParams` may create through the Manager API and
then construct a `ManagedWallet` from that generation's exact `Config`,
`Manager`, and `Wallet`. The Manager and Wallet remain registered with the
harness until `ReloadWallet` transfers ownership to the replacement.

Two convenience wrappers remain for cases that need nothing else:

- `(*HarnessTest).CreateEmptyWallet`
- `(*HarnessTest).CreateFundedWallet`

Funding is also available on its own through `(*HarnessTest).FundWallet` and
`(*HarnessTest).FundWalletOfType`, and addresses through
`(*HarnessTest).NewWalletAddress` and `(*HarnessTest).NewWalletAddressOfType`.

Manager-focused tests should continue to create wallets through the Manager API
directly. Component tests using the standard fixture that need reload handles
should use `NewManagedWallet` instead.

## Fast Scrypt

`bwtest` sets `waddrmgr.DefaultScryptOptions` to `waddrmgr.FastScryptOptions` via
an `init()` function. Any package that imports `bwtest` (including `itest`)
automatically benefits from faster key derivation, avoiding CPU exhaustion and
timeouts — especially when running with `-race`.
