package dcr

import (
	"context"
	"net"
	"time"

	"decred.org/dcrwallet/v4/p2p"
	"decred.org/dcrwallet/v4/spv"
	dcrwallet "decred.org/dcrwallet/v4/wallet"
	"github.com/decred/dcrd/addrmgr/v2"
)

// StartSync connects the wallet to the blockchain network via SPV and returns
// immediately. The wallet stays connected in the background until the provided
// ctx is canceled or either StopSync or CloseWallet is called.
func (w *Wallet) StartSync(ctx context.Context, ntfns *spv.Notifications, connectPeers ...string) error {
	// Initialize the ctx to use for sync. Will error if sync was already
	// started.
	ctx, err := w.InitializeSyncContext(ctx)
	if err != nil {
		return err
	}

	w.log.Info("Starting sync...")

	addr := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	amgr := addrmgr.New(w.dir, net.LookupIP)
	lp := p2p.NewLocalPeer(w.ChainParams(), addr, amgr)

	// We must create a new syncer for every attempt or we will get a
	// closing closed channel panic when close(s.initialSyncDone) happens
	// for the second time inside dcrwallet.
	newSyncer := func() *spv.Syncer {
		w.syncerMtx.Lock()
		defer w.syncerMtx.Unlock()
		syncer := spv.NewSyncer(w.mainWallet, lp)
		if len(connectPeers) > 0 {
			syncer.SetPersistentPeers(connectPeers)
		}
		syncer.SetNotifications(ntfns)

		// TODO: Set a birthday to sync from. I don't think dcrwallet allows
		// this currently.

		w.syncer = syncer
		w.SetNetworkBackend(syncer)
		return syncer
	}

	// Start the syncer in a goroutine, monitor when the sync ctx is canceled
	// and then disconnect the sync.
	go func() {
		for {
			syncer := newSyncer()
			err := syncer.Run(ctx)
			if ctx.Err() != nil {
				w.syncerMtx.Lock()
				defer w.syncerMtx.Unlock()
				// sync ctx canceled, quit syncing
				w.syncer = nil
				w.SetNetworkBackend(nil)
				w.SyncEnded(nil)
				return
			}

			w.log.Errorf("SPV synchronization ended. Trying again in 10 seconds: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second * 10):
			}
		}
	}()

	return nil
}

// IsSyncing returns true if the wallet is catching up to the mainchain's best
// block.
func (w *Wallet) IsSyncing(ctx context.Context) bool {
	synced, _ := w.IsSynced(ctx)
	if synced {
		return false
	}
	return w.IsSyncingOrSynced()
}

// IsSynced returns true if the wallet has synced up to the best block on the
// mainchain.
func (w *Wallet) IsSynced(ctx context.Context) (bool, int32) {
	w.syncerMtx.RLock()
	defer w.syncerMtx.RUnlock()
	if w.syncer != nil {
		return w.syncer.Synced(ctx)
	}
	return false, 0
}

// RescanProgressFromHeight rescans for relevant transactions in all blocks in
// the main chain starting at startHeight. Progress notifications and any
// errors are sent to the channel p. This function blocks until the rescan
// completes or ends in an error. p is closed before returning.
func (w *Wallet) RescanProgressFromHeight(ctx context.Context,
	startHeight int32, p chan<- dcrwallet.RescanProgress) {
	w.syncerMtx.RLock()
	defer w.syncerMtx.RUnlock()
	w.mainWallet.RescanProgressFromHeight(ctx, w.syncer, startHeight, p)
}
