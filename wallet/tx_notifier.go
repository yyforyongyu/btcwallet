// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// txNotifier lets the syncer announce committed observations without owning
// subscriptions or changing the result of a transaction operation.
type txNotifier interface {
	// notifyTx prepares one Wallet detail and offers it without waiting for
	// consumers. Preparation failure skips delivery and never fails the write.
	notifyTx(ctx context.Context, txHash chainhash.Hash)
}

// txSubscriptions provides the syncer's notification capability.
var _ txNotifier = (*txSubscriptions)(nil)

// notifyTx reads one committed observation outside the subscription mutex and
// copies its mutable payload for each current subscriber. Delivery is best
// effort: concurrent writes may change the observed state, and read failures
// cannot change the already successful producer operation.
func (s *txSubscriptions) notifyTx(ctx context.Context, txHash chainhash.Hash) {
	observedAt := time.Now()

	// Avoid Store work without subscribers; this is not a recipient snapshot.
	// Registration may race preparation and there is no delivery eligibility
	// promise for a subscription created during an observation.
	s.mu.Lock()
	hasSubscribers := len(s.subscribers) != 0
	s.mu.Unlock()

	if !hasSubscribers {
		return
	}

	// Read the same Store tip used by Wallet readers, carrying the producer's
	// context rather than the legacy SyncedTo accessor's background context.
	info, err := s.store.GetWallet(ctx, s.walletName)
	if err != nil {
		log.Warnf("Unable to read notification wallet tip: %v", err)

		return
	}

	tip, err := db.OptionalBlockStampFromBlock(info.SyncedTo)
	if err != nil {
		log.Errorf("Unable to decode notification wallet tip: %v", err)

		return
	}

	detail, err := getTxDetail(
		ctx, s.store, s.walletID, txHash, tip.Height, s.chainParams,
	)
	if err != nil {
		// Cancellation and concurrent removal are normal best-effort gaps.
		// Unexpected read failures are visible in logs, not producer results.
		if ctx.Err() == nil && !errors.Is(err, ErrTxNotFound) {
			log.Errorf("Unable to prepare transaction notification: %v", err)
		}

		return
	}

	// Published covers both unconfirmed and confirmed transactions. Other
	// states are bookkeeping transitions outside this observation contract.
	if detail.Status != TxStatusPublished {
		return
	}

	// Membership, offers, and closure share one lock. Consumers receive
	// directly from their channel and never need this mutex.
	s.mu.Lock()
	defer s.mu.Unlock()

	for sub := range s.subscribers {
		sub.notify(&TxEvent{
			Detail:    detail.clone(),
			Timestamp: observedAt,
		})
	}
}

// notify retains the incoming notification, discarding the oldest if full.
// The caller holds txSubscriptions.mu, excluding other producers and
// closure; consumers still receive freely without taking that mutex.
func (s *txSubscription) notify(event *TxEvent) {
	select {
	case s.events <- event:
		return
	default:
	}

	// The failed send can race a consumer, so the queue may no longer be
	// full. Evict only if an item remains; either way a slot is available.
	select {
	case <-s.events:
		log.Debug("Discarding oldest transaction event")
	default:
	}

	// No other producer can fill the freed slot under the shared mutex.
	// Keep the final offer explicitly nonblocking for the caller.
	select {
	case s.events <- event:
	default:
	}
}
