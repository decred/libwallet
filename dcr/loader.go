package dcr

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"decred.org/dcrwallet/v4/wallet"
	_ "decred.org/dcrwallet/v4/wallet/drivers/bdb"
	"decred.org/dcrwallet/v4/wallet/udb"
	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/decred/libwallet/mnemonic"
)

const (
	walletDbName = "wallet.db"
	entropyBytes = 18 // 144 bits
)

// WalletExistsAt returns whether a wallet database file exists at the specified
// directory. This may return an error for unexpected I/O failures.
func WalletExistsAt(dataDir string) (bool, error) {
	return fileExists(filepath.Join(dataDir, walletDbName))
}

// CreateWallet creates and opens an SPV wallet. If recovery params is not
// provided, a new seed is generated and used. The seed is encrypted with the
// provided passphrase and can be revealed for backup later by providing the
// passphrase.
func CreateWallet(ctx context.Context, params CreateWalletParams, recovery *RecoveryCfg) (*Wallet, error) {
	chainParams, err := ParseChainParams(params.Net)
	if err != nil {
		return nil, fmt.Errorf("error parsing chain params: %w", err)
	}

	if exists, err := WalletExistsAt(params.DataDir); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("wallet at %q already exists", filepath.Join(params.DataDir, walletDbName))
	}

	// Ensure the data directory for the network exists.
	if err := checkCreateDir(params.DataDir); err != nil {
		return nil, fmt.Errorf("check new wallet data directory error: %w", err)
	}

	var (
		seed, seedPass, tweakedSeed []byte
		birthday                    time.Time
		seedType                    SeedType
	)

	if recovery != nil {
		if recovery.UseLocalSeed {
			wd, err := retrieveWalletData(params.DataDir)
			if err != nil {
				return nil, fmt.Errorf("unable to get wallet data: %v", err)
			}
			encSeed, err := hex.DecodeString(wd.EncryptedSeedHex)
			if err != nil {
				return nil, fmt.Errorf("unable to decode encrypted hex seed: %v", err)
			}
			seed, err = DecryptData(encSeed, params.Pass)
			if err != nil {
				return nil, fmt.Errorf("unable to decrypt wallet seed: %v", err)
			}
			if len(wd.EncryptedSeedPassHex) != 0 {
				encSeedPass, err := hex.DecodeString(wd.EncryptedSeedPassHex)
				if err != nil {
					return nil, fmt.Errorf("unable to decode encrypted seed pass: %v", err)
				}
				seedPass, err = DecryptData(encSeedPass, params.Pass)
				if err != nil {
					return nil, fmt.Errorf("unable to decrypt wallet seed pass: %v", err)
				}
			}
			birthday = time.Unix(wd.Birthday, 0)
			seedType = wd.SeedType
		} else {
			seed, seedPass, birthday, seedType = recovery.Seed, recovery.SeedPass, recovery.Birthday, recovery.SeedType
		}
	} else {
		seed, err = hdkeychain.GenerateSeed(entropyBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to generate random seed: %v", err)
		}
		birthday = time.Now()
		// Seed type is default fifteen words.
	}

	switch seedType {
	case STFifteenWords:
		// Applying the seed pass to 15 word wallets breaks existing
		// wallets when no pass is supplied. Also, the mnemonic cannot
		// be used by other decred software if a passphrase is applied.
		if len(seedPass) != 0 {
			return nil, errors.New("seed passphrase cannot be used with 15 word mnemonics")
		}
		// Adjust seed to create the same wallet as bison wallet.
		b := make([]byte, len(seed)+4)
		copy(b, seed)
		binary.BigEndian.PutUint32(b[len(seed):], 42)
		ts := blake256.Sum256(b)
		tweakedSeed = ts[:]
	case STTwelveWords, STTwentyFourWords:
		words, err := mnemonic.GenerateMnemonic(seed)
		if err != nil {
			return nil, fmt.Errorf("unable to recreate seed mnemonic: %v", err)
		}
		// Apply even if password is null.
		tweakedSeed = mnemonic.ApplyPassphrase(seed, seedPass, words)
	}

	_, _, _, acctKeySLIP0044Priv, err := udb.HDKeysFromSeed(tweakedSeed, chainParams)
	if err != nil {
		return nil, err
	}
	defer acctKeySLIP0044Priv.Zero()
	xpub := acctKeySLIP0044Priv.Neuter()
	wd, err := saveWalletData(seed, seedPass, xpub.String(), birthday, params.DataDir, params.Pass, seedType)
	if err != nil {
		return nil, fmt.Errorf("saveWalletData error: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	// Create the wallet database using the specified db driver.
	dbPath := filepath.Join(params.DataDir, walletDbName)
	db, err := wallet.CreateDB(params.DbDriver, dbPath)
	if err != nil {
		return nil, fmt.Errorf("CreateDB error: %w", err)
	}

	bailOnWallet := true // changed to false if there are no errors below
	defer func() {
		if bailOnWallet {
			if err := db.Close(); err != nil {
				fmt.Println("Error closing database after CreateWallet error:", err)
			}

			// It was asserted above that there is no existing database file, so
			// deleting anything won't destroy a wallet in use. Attempt to
			// remove any wallet remnants.
			_ = os.Remove(params.DataDir)
		}
	}()

	// Initialize the newly created database for the wallet before opening.
	err = wallet.Create(ctx, db, nil, params.Pass, tweakedSeed, chainParams)
	if err != nil {
		return nil, fmt.Errorf("wallet.Create error: %w", err)
	}

	// Open the newly-created wallet.
	w, err := wallet.Open(ctx, newWalletConfig(db, chainParams))
	if err != nil {
		return nil, fmt.Errorf("wallet.Open error: %w", err)
	}

	birthState := &udb.BirthdayState{
		Time:        birthday.Add(time.Hour * -24),
		SetFromTime: true,
	}

	if err := w.SetBirthState(ctx, birthState); err != nil {
		return nil, fmt.Errorf("wallet.SetBirthState error: %w", err)
	}

	// Upgrade the coin type if this is not a wallet recovery. If it's a
	// recovery, extend the internal and external address indices.
	if recovery == nil {
		err = w.UpgradeToSLIP0044CoinType(ctx)
		if err != nil {
			return nil, fmt.Errorf("upgrade new wallet coin type error: %w", err)
		}
	} else if recovery.NumExternalAddresses > 0 || recovery.NumInternalAddresses > 0 {
		err = extendAddresses(ctx, recovery.NumExternalAddresses, recovery.NumInternalAddresses, w)
		if err != nil {
			return nil, fmt.Errorf("failed to set starting address indexes: %w", err)
		}
	}

	bailOnWallet = false
	return &Wallet{
		dir:         params.DataDir,
		dbDriver:    params.DbDriver,
		chainParams: chainParams,
		log:         params.Logger,
		metaData:    wd,
		db:          db,
		mainWallet:  w,
		syncHelper:  &syncHelper{log: params.Logger},
	}, nil
}

// CreateWatchOnlyWallet creates and opens a watchonly SPV wallet.
func CreateWatchOnlyWallet(ctx context.Context, extendedPubKey string, params CreateWalletParams, useLocalSeed bool) (*Wallet, error) {
	chainParams, err := ParseChainParams(params.Net)
	if err != nil {
		return nil, fmt.Errorf("error parsing chain params: %w", err)
	}

	if exists, err := WalletExistsAt(params.DataDir); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("wallet at %q already exists", params.DataDir)
	}

	// Ensure the data directory for the network exists.
	if err := checkCreateDir(params.DataDir); err != nil {
		return nil, fmt.Errorf("check new wallet data directory error: %w", err)
	}

	if useLocalSeed {
		wd, err := retrieveWalletData(params.DataDir)
		if err != nil {
			return nil, fmt.Errorf("unable to get wallet data: %v", err)
		}
		extendedPubKey = wd.DefaultAccountXPub
	}

	xpub, err := hdkeychain.NewKeyFromString(extendedPubKey, chainParams)
	if err != nil {
		return nil, fmt.Errorf("unable to parse extended key: %w", err)
	}

	wd, err := saveWalletData(nil, nil, xpub.String(), time.Time{}, params.DataDir, nil, 0) // password not required
	if err != nil {
		return nil, fmt.Errorf("saveWalletData error: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	// Create the wallet database using the specified db driver.
	dbPath := filepath.Join(params.DataDir, walletDbName)
	db, err := wallet.CreateDB(params.DbDriver, dbPath)
	if err != nil {
		return nil, fmt.Errorf("CreateDB error: %w", err)
	}

	bailOnWallet := true // changed to false if there are no errors below
	defer func() {
		if bailOnWallet {
			err := db.Close()
			if err != nil {
				fmt.Println("Error closing database after CreateWallet error:", err)
			}

			// It was asserted above that there is no existing database file, so
			// deleting anything won't destroy a wallet in use. Attempt to
			// remove any wallet remnants.
			_ = os.Remove(params.DataDir)
		}
	}()

	// Initialize the newly created database for the wallet before opening.
	err = wallet.CreateWatchOnly(ctx, db, extendedPubKey, nil, chainParams)
	if err != nil {
		return nil, fmt.Errorf("wallet.Create error: %w", err)
	}

	// Open the newly-created wallet.
	w, err := wallet.Open(ctx, newWalletConfig(db, chainParams))
	if err != nil {
		return nil, fmt.Errorf("wallet.Open error: %w", err)
	}

	bailOnWallet = false
	return &Wallet{
		dir:         params.DataDir,
		dbDriver:    params.DbDriver,
		chainParams: chainParams,
		log:         params.Logger,
		metaData:    wd,
		db:          db,
		mainWallet:  w,
		syncHelper:  &syncHelper{log: params.Logger},
	}, nil
}

// LoadWallet loads a previously created SPV wallet. The wallet must be opened
// via its OpenWallet method before it can be used.
func LoadWallet(ctx context.Context, params OpenWalletParams) (*Wallet, error) {
	if exists, err := WalletExistsAt(params.DataDir); err != nil {
		return nil, err
	} else if !exists {
		return nil, fmt.Errorf("wallet at %q doesn't exist", params.DataDir)
	}

	chainParams, err := ParseChainParams(params.Net)
	if err != nil {
		return nil, fmt.Errorf("error parsing chain params: %w", err)
	}

	wd, err := retrieveWalletData(params.DataDir)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		dir:         params.DataDir,
		dbDriver:    params.DbDriver,
		chainParams: chainParams,
		log:         params.Logger,
		metaData:    wd,
		syncHelper:  &syncHelper{log: params.Logger},
	}, nil
}
