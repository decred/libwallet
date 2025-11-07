package dcr

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SeedType defines the type of seed used by the wallet. Currently all use bip39
// words but they are different lengths.
type SeedType int

const (
	// STFifteenWords encodes a birthday along with the seed. It is also
	// used by bison wallet and has a tweak that causes it to produce the
	// same wallet.
	STFifteenWords    SeedType = iota // 0
	STTwelveWords                     // 1
	STTwentyFourWords                 // 2
)

const walletDataFileName = "walletdata.json"

type walletData struct {
	EncryptedSeedHex     string   `json:"encryptedseedhex,omitempty"`
	EncryptedSeedPassHex string   `json:"encryptedseedpasshex,omitempty"`
	SeedType             SeedType `json:"seedtype,omitempty"`
	DefaultAccountXPub   string   `json:"defaultaccountxpub,omitempty"`
	Birthday             int64    `json:"birthday,omitempty"`
}

func saveWalletData(seed, seedPass []byte, defaultAccountXPub string, birthday time.Time, dataDir string, walletPass []byte, seedType SeedType) (*walletData, error) {
	encSeed, err := EncryptData(seed, walletPass)
	if err != nil {
		return nil, fmt.Errorf("seed encryption error: %v", err)
	}

	encSeedPassHex := ""
	if len(seedPass) != 0 {
		encSeedPass, err := EncryptData(seedPass, walletPass)
		if err != nil {
			return nil, fmt.Errorf("seed pass encryption error: %v", err)
		}
		encSeedPassHex = hex.EncodeToString(encSeedPass)
	}

	encSeedHex := hex.EncodeToString(encSeed)
	wd := &walletData{
		EncryptedSeedHex:     encSeedHex,
		EncryptedSeedPassHex: encSeedPassHex,
		DefaultAccountXPub:   defaultAccountXPub,
		Birthday:             birthday.Unix(),
		SeedType:             seedType,
	}
	file, err := json.MarshalIndent(wd, "", " ")
	if err != nil {
		return nil, fmt.Errorf("unable to marshal wallet data: %v", err)
	}
	fp := filepath.Join(dataDir, walletDataFileName)
	err = os.WriteFile(fp, file, 0644)
	if err != nil {
		return nil, fmt.Errorf("unable to write wallet data to file: %v", err)
	}
	return wd, nil
}

// retrieveWalletData returns the wallet data from the data dir.
func retrieveWalletData(dataDir string) (*walletData, error) {
	fp := filepath.Join(dataDir, walletDataFileName)
	b, err := os.ReadFile(fp)
	if err != nil {
		if os.IsNotExist(err) {
			return new(walletData), nil
		}
		return nil, fmt.Errorf("unable to read wallet data file: %v", err)
	}
	var wd walletData
	if err := json.Unmarshal(b, &wd); err != nil {
		return nil, fmt.Errorf("unable to unmarshal wallet data file: %v", err)
	}
	return &wd, nil
}
