package asset

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"decred.org/dcrdex/client/mnemonic"
	"github.com/decred/slog"
)

const entropyBytes = 18 // 144 bits

type WalletBase struct {
	log     slog.Logger
	dataDir string
	network Network

	mtx                      sync.Mutex
	traits                   WalletTrait
	encryptedSeed            []byte
	defaultAccountXPub       string
	birthday                 time.Time
	accountDiscoveryRequired bool

	*syncHelper
}

// NewWalletBase initializes a WalletBase using the information provided. The
// wallet's seed is encrypted and saved, along with other basic wallet info.
func NewWalletBase(params OpenWalletParams, seed, walletPass []byte, defaultAccountXPub string, birthday time.Time, traits WalletTrait) (*WalletBase, error) {
	isWatchOnly, isRestored := isWatchOnly(traits), isRestored(traits)
	if isWatchOnly && isRestored {
		return nil, fmt.Errorf("invalid wallet traits: restored wallet cannot be watch only")
	}

	hasSeedAndWalletPass := len(seed) > 0 || len(walletPass) > 0

	switch {
	case isWatchOnly && hasSeedAndWalletPass:
		return nil, fmt.Errorf("invalid arguments for watch only wallet")
	case !isWatchOnly && !hasSeedAndWalletPass:
		return nil, fmt.Errorf("seed AND private passphrase are required")
	}

	if hasSeedAndWalletPass && len(seed) != entropyBytes {
		return nil, fmt.Errorf("seed should be %d bytes long but go %d", entropyBytes, len(seed))
	}

	var encryptedSeed []byte
	var err error
	if !isWatchOnly {
		encryptedSeed, err = EncryptData(seed, walletPass)
		if err != nil {
			return nil, fmt.Errorf("seed encryption error: %v", err)
		}
	}

	// Account discovery is only required for restored wallets.
	accountDiscoveryRequired := isRestored

	if err := saveWalletData(encryptedSeed, defaultAccountXPub, birthday, params.DataDir); err != nil {
		return nil, err
	}

	return &WalletBase{
		log:                      params.Logger,
		dataDir:                  params.DataDir,
		network:                  params.Net,
		traits:                   traits,
		encryptedSeed:            encryptedSeed,
		defaultAccountXPub:       defaultAccountXPub,
		birthday:                 birthday,
		accountDiscoveryRequired: accountDiscoveryRequired,
		syncHelper:               &syncHelper{log: params.Logger},
	}, nil
}

// OpenWalletBase loads basic information for an existing wallet from the
// provided params.
func OpenWalletBase(params OpenWalletParams) (*WalletBase, error) {
	wd, err := WalletData(params.DataDir)
	if err != nil {
		return nil, err
	}

	encSeed, err := hex.DecodeString(wd.EncryptedSeedHex)
	if err != nil {
		return nil, fmt.Errorf("unable to decode encrypted hex seed: %v", err)
	}

	w := &WalletBase{
		log:                params.Logger,
		dataDir:            params.DataDir,
		network:            params.Net,
		syncHelper:         &syncHelper{log: params.Logger},
		encryptedSeed:      encSeed,
		defaultAccountXPub: wd.DefaultAccountXPub,
		birthday:           time.Unix(wd.Birthday, 0),
	}

	return w, nil
}

func (w *WalletBase) DataDir() string {
	return w.dataDir
}

func (w *WalletBase) Network() Network {
	return w.network
}

// DecryptSeed decrypts the encrypted wallet seed using the provided passphrase
// and returns the mnemonic.
func (w *WalletBase) DecryptSeed(passphrase []byte) (string, error) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	if w.encryptedSeed == nil {
		return "", fmt.Errorf("seed has been verified")
	}

	seed, err := DecryptData(w.encryptedSeed, passphrase)
	if err != nil {
		return "", err
	}
	return mnemonic.GenerateMnemonic(seed, w.birthday)
}

func (w *WalletBase) ReEncryptSeed(oldPass, newPass []byte) error {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	if w.encryptedSeed == nil {
		return nil
	}

	reEncryptedSeed, err := ReEncryptData(w.encryptedSeed, oldPass, newPass)
	if err != nil {
		return err
	}

	if err := saveWalletData(reEncryptedSeed, w.defaultAccountXPub, w.birthday, w.dataDir); err != nil {
		return err
	}

	w.encryptedSeed = reEncryptedSeed
	return nil
}

func (w *WalletBase) IsWatchOnly() bool {
	w.mtx.Lock()
	defer w.mtx.Unlock()
	return isWatchOnly(w.traits)
}

func (w *WalletBase) IsRestored() bool {
	w.mtx.Lock()
	defer w.mtx.Unlock()
	return isRestored(w.traits)
}

func (w *WalletBase) DefaultAccountXPub() string {
	return w.defaultAccountXPub
}
