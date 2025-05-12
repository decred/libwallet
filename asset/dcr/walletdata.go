package dcr

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const walletDataFileName = "walletdata.json"

type walletData struct {
	// seedMtx protects the EncryptedSeedHex field which may be modified when the
	// wallet password is changed.
	seedMtx            sync.Mutex
	EncryptedSeedHex   string `json:"encryptedseedhex,omitempty"`
	DefaultAccountXPub string `json:"defaultaccountxpub,omitempty"`
	Birthday           int64  `json:"birthday,omitempty"`
}

func SaveWalletData(seed []byte, defaultAccountXPub string, birthday time.Time, dataDir string, walletPass []byte) (*walletData, error) {
	encSeed, err := EncryptData(seed, walletPass)
	if err != nil {
		return nil, fmt.Errorf("seed encryption error: %v", err)
	}

	encSeedHex := hex.EncodeToString(encSeed)
	wd := &walletData{
		EncryptedSeedHex:   encSeedHex,
		DefaultAccountXPub: defaultAccountXPub,
		Birthday:           birthday.Unix(),
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

// RetreiveWalletData returns the wallet data from the data dir.
func RetreiveWalletData(dataDir string) (*walletData, error) {
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
