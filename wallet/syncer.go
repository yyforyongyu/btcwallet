package wallet

import (
	"context"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

// syncState represents the synchronization status of the wallet with the
// blockchain.
type syncState uint32

const (
	// syncStateBackendSyncing indicates the wallet is waiting for the chain
	// backend to finish syncing.
	syncStateBackendSyncing syncState = iota

	// syncStateSyncing indicates the wallet is running but catching up to
	// the chain tip (or rewinding).
	syncStateSyncing

	// syncStateSynced indicates the wallet is running and synced to the
	// chain tip.
	syncStateSynced

	// syncStateRescanning indicates the wallet is running a historical
	// scan for specific user-provided targets, such as accounts or
	// addresses, without rewinding the global synchronization state.
	syncStateRescanning
)

// String returns the string representation of a syncState.
func (s syncState) String() string {
	switch s {
	case syncStateBackendSyncing:
		return "backend-syncing"

	case syncStateSyncing:
		return "syncing"

	case syncStateSynced:
		return "synced"

	case syncStateRescanning:
		return "rescanning"

	default:
		return "unknown sync state"
	}
}

// scanType represents the type of rescan being requested.
type scanType uint8

const (
	// scanTypeRewind represents a full rescan which rewinds the wallet's
	// state to a specific point and scans forward.
	scanTypeRewind scanType = iota

	// scanTypeTargeted represents a targeted rescan for specific
	// addresses or accounts without altering the global sync state.
	scanTypeTargeted
)

// scanReq is an internal request to perform a rescan.
type scanReq struct {
	// typ specifies the type of rescan to perform.
	typ scanType

	// startBlock specifies the block height and hash to start the rescan
	// from.
	startBlock waddrmgr.BlockStamp

	// targets specifies the accounts to scan for. This is only used for
	// targeted rescans.
	targets []waddrmgr.AccountScope
}

// chainSyncer is a private interface that abstracts the chain synchronization
// logic, allowing it to be mocked for testing the wallet and controller.
type chainSyncer interface {
	// run executes the main synchronization loop.
	run(ctx context.Context) error

	// requestScan submits a rescan job to the syncer.
	requestScan(ctx context.Context, req *scanReq) error

	// syncState returns the current synchronization state.
	syncState() syncState
}
