package dcr

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"

	"decred.org/dcrwallet/v4/spv"
	"decred.org/dcrwallet/v4/wallet"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/libwallet/asset"
	"github.com/decred/slog"
)

type mainWallet = wallet.Wallet

type Wallet struct {
	*asset.WalletBase
	dir         string
	dbDriver    string
	chainParams *chaincfg.Params
	log         slog.Logger

	db wallet.DB
	*mainWallet

	syncerMtx sync.RWMutex
	syncer    *spv.Syncer
}

// MainWallet returns the main dcr wallet with the core wallet functionalities.
func (w *Wallet) MainWallet() *wallet.Wallet {
	return w.mainWallet
}

// WalletOpened returns true if the main wallet has been opened.
func (w *Wallet) WalletOpened() bool {
	return w.mainWallet != nil
}

// OpenWallet opens the wallet database and the main wallet.
func (w *Wallet) OpenWallet(ctx context.Context) error {
	if w.mainWallet != nil {
		return fmt.Errorf("wallet is already open")
	}

	w.log.Info("Opening wallet...")
	db, err := wallet.OpenDB(w.dbDriver, filepath.Join(w.dir, walletDbName))
	if err != nil {
		return fmt.Errorf("wallet.OpenDB error: %w", err)
	}

	dcrw, err := wallet.Open(ctx, newWalletConfig(db, w.chainParams))
	if err != nil {
		// If this function does not return to completion the database must be
		// closed.  Otherwise, because the database is locked on open, any
		// other attempts to open the wallet will hang, and there is no way to
		// recover since this db handle would be leaked.
		if err := db.Close(); err != nil {
			w.log.Errorf("Failed to close wallet database after OpenWallet error: %v", err)
		}
		return fmt.Errorf("wallet.Open error: %w", err)
	}

	w.db = db
	w.mainWallet = dcrw
	return nil
}

// CloseWallet stops any active network synchronization and closes the wallet
// database.
func (w *Wallet) CloseWallet() error {
	w.log.Info("Closing wallet")
	w.StopSync()
	w.WaitForSyncToStop()

	w.log.Trace("Closing wallet db")
	if err := w.db.Close(); err != nil {
		return fmt.Errorf("Close wallet db error: %w", err)
	}

	w.log.Info("Wallet closed")
	return nil
}

// Shutdown closes the main wallet and any other resources in use.
func (w *Wallet) Shutdown() error {
	return w.CloseWallet()
}
