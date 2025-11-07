package dcr

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	dexmnemonic "decred.org/dcrdex/client/mnemonic"
	"decred.org/dcrwallet/v4/spv"
	"decred.org/dcrwallet/v4/wallet"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/libwallet/mnemonic"
	"github.com/decred/slog"
)

type mainWallet = wallet.Wallet

type Wallet struct {
	dir         string
	dbDriver    string
	chainParams *chaincfg.Params
	log         slog.Logger

	// seedMtx protects the metaData.EncryptedSeedHex field which may be
	// modified when the wallet password is changed.
	seedMtx  sync.Mutex
	metaData *walletData
	db       wallet.DB
	*mainWallet

	syncerMtx sync.RWMutex
	syncer    *spv.Syncer
	*syncHelper
}

// MainWallet returns the main dcr wallet with the core wallet functionalities.
func (w *Wallet) MainWallet() *wallet.Wallet {
	return w.mainWallet
}

// DecryptSeed decrypts the encrypted wallet seed using the provided passphrase
// and returns the mnemonic.
func (w *Wallet) DecryptSeed(passphrase []byte) (string, error) {
	w.seedMtx.Lock()
	defer w.seedMtx.Unlock()

	encryptedSeed, err := hex.DecodeString(w.metaData.EncryptedSeedHex)
	if err != nil {
		return "", fmt.Errorf("unable to decode encrypted hex seed: %v", err)
	}

	seed, err := DecryptData(encryptedSeed, passphrase)
	if err != nil {
		return "", err
	}

	switch w.metaData.SeedType {
	case STFifteenWords:
		return dexmnemonic.GenerateMnemonic(seed, time.Unix(w.metaData.Birthday, 0))
	case STTwelveWords, STTwentyFourWords:
		return mnemonic.GenerateMnemonic(seed)
	default:
		return "", fmt.Errorf("invalid saved seed length %d", len(seed))
	}
}

// ReEncryptSeed reads the seed with the old pass and encrypts it with the new pass.
func (w *Wallet) ReEncryptSeed(oldPass, newPass []byte) error {
	w.seedMtx.Lock()
	defer w.seedMtx.Unlock()

	if w.metaData.EncryptedSeedHex == "" {
		return errors.New("encrypted seed does not exist")
	}

	encryptedSeed, err := hex.DecodeString(w.metaData.EncryptedSeedHex)
	if err != nil {
		return fmt.Errorf("unable to decode encrypted hex seed: %v", err)
	}

	seed, err := DecryptData(encryptedSeed, oldPass)
	if err != nil {
		return err
	}

	var seedPass []byte
	if len(w.metaData.EncryptedSeedPassHex) != 0 {
		encSeedPass, err := hex.DecodeString(w.metaData.EncryptedSeedPassHex)
		if err != nil {
			return fmt.Errorf("unable to decode encrypted seed pass: %v", err)
		}
		seedPass, err = DecryptData(encSeedPass, oldPass)
		if err != nil {
			return fmt.Errorf("unable to decrypt wallet seed pass: %v", err)
		}
	}

	birthday := time.Unix(w.metaData.Birthday, 0)
	updatedMetaData, err := saveWalletData(seed, seedPass, w.metaData.DefaultAccountXPub, birthday, w.dir, newPass, w.metaData.SeedType)
	if err != nil {
		return err
	}

	// Update only the EncryptedSeedHex and pass field since we've held the seedMtx lock
	// above.
	w.metaData.EncryptedSeedHex = updatedMetaData.EncryptedSeedHex
	w.metaData.EncryptedSeedPassHex = updatedMetaData.EncryptedSeedPassHex
	return nil
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
		return fmt.Errorf("close wallet db error: %w", err)
	}

	w.log.Info("Wallet closed")
	return nil
}

// Shutdown closes the main wallet and any other resources in use.
func (w *Wallet) Shutdown() error {
	return w.CloseWallet()
}
