package wallet

import (
	"context"
	"time"
)

// newManagedWallet constructs a Wallet from backend-validated storage data.
// The backend remains the owner of every resource referenced by data.
func (m *Manager) newManagedWallet(cfg Config, data *walletData) *Wallet {
	lockTimer := time.NewTimer(0)
	if !lockTimer.Stop() {
		<-lockTimer.C
	}

	lifetimeCtx, cancel := context.WithCancel(context.Background())

	w := &Wallet{
		cfg:               cfg,
		id:                data.id,
		addrStore:         data.addressStore,
		store:             data.store,
		cache:             newStoreRuntimeCache(data.store),
		keyVault:          data.vault,
		unsafeVault:       data.vault,
		txStore:           data.transactionStore,
		requestChan:       make(chan any),
		lifetimeCtx:       lifetimeCtx,
		cancel:            cancel,
		requestStop:       m.requestWalletStop,
		lockTimer:         lockTimer,
		masterFingerprint: data.masterFingerprint,
		isWatchOnly:       data.isWatchOnly,
	}

	// Enroll this Wallet's lifetime-scoped chain subscription before
	// publication. Its existing sync worker owns the subscription and
	// remains the sole event processor.
	w.sync = newSyncer(
		cfg, w.addrStore, w.txStore, w, w.store, w.id,
		cfg.Chain.SubscribeChainEvents(lifetimeCtx),
	)
	w.state = newWalletState(w.sync)

	return w
}
