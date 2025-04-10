package asset

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const walletDataFileName = "walletdata.json"

type walletData struct {
	EncryptedSeedHex   string `json:"encryptedseedhex,omitempty"`
	DefaultAccountXPub string `json:"defaultaccountxpub,omitempty"`
	Birthday           int64  `json:"birthday,omitempty"`
}

func saveWalletData(encSeed []byte, defaultAccountXPub string, birthday time.Time, dataDir string) error {
	encSeedHex := hex.EncodeToString(encSeed)
	wd := walletData{
		EncryptedSeedHex:   encSeedHex,
		DefaultAccountXPub: defaultAccountXPub,
		Birthday:           birthday.Unix(),
	}
	file, err := json.MarshalIndent(wd, "", " ")
	if err != nil {
		return fmt.Errorf("unable to marshal wallet data: %v", err)
	}
	fp := filepath.Join(dataDir, walletDataFileName)
	err = os.WriteFile(fp, file, 0644)
	if err != nil {
		return fmt.Errorf("unable to write wallet data to file: %v", err)
	}
	return nil
}

// WalletData returns the wallet data from the data dir.
func WalletData(dataDir string) (*walletData, error) {
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
