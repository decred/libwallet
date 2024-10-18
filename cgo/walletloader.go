package main

import "C"
import (
	"context"
	"encoding/json"
	"sync"

	"decred.org/dcrdex/client/mnemonic"
	"github.com/decred/libwallet/asset"
	"github.com/decred/libwallet/asset/dcr"
	"github.com/decred/slog"
)

const emptyJsonObject = "{}"

type wallet struct {
	*dcr.Wallet
	log slog.Logger

	sync.WaitGroup
	ctx       context.Context
	cancelCtx context.CancelFunc

	syncStatusMtx                                                       sync.RWMutex
	syncStatusCode                                                      SyncStatusCode
	targetHeight, cfiltersHeight, headersHeight, rescanHeight, numPeers int
	rescanning                                                          bool
}

//export createWallet
func createWallet(cName, cDataDir, cNet, cPass, cMnemonic *C.char) *C.char {
	walletsMtx.Lock()
	defer walletsMtx.Unlock()
	if !initialized {
		return errCResponse("libwallet is not initialized")
	}

	name := goString(cName)
	if _, exists := wallets[name]; exists {
		return errCResponse("wallet already exists with name: %q", name)
	}

	network, err := asset.NetFromString(goString(cNet))
	if err != nil {
		return errCResponse("%v", err)
	}

	logger := logBackend.Logger("[" + name + "]")
	logger.SetLevel(slog.LevelTrace)
	params := asset.CreateWalletParams{
		OpenWalletParams: asset.OpenWalletParams{
			Net:      network,
			DataDir:  goString(cDataDir),
			DbDriver: "bdb", // use badgerdb for mobile!
			Logger:   logger,
		},
		Pass: []byte(goString(cPass)),
	}

	mnemonicStr := goString(cMnemonic)
	var recoveryConfig *asset.RecoveryCfg
	if mnemonicStr != "" {
		seed, birthday, err := mnemonic.DecodeMnemonic(mnemonicStr)
		if err != nil {
			return errCResponse("unable to decode wallet mnemonic: %v", err)
		}
		recoveryConfig = &asset.RecoveryCfg{
			Seed:     seed,
			Birthday: birthday,
		}
	}
	walletCtx, cancel := context.WithCancel(mainCtx)

	w, err := dcr.CreateWallet(walletCtx, params, recoveryConfig)
	if err != nil {
		cancel()
		return errCResponse("%v", err)
	}

	wallets[name] = &wallet{
		Wallet:    w,
		log:       logger,
		ctx:       walletCtx,
		cancelCtx: cancel,
	}
	return successCResponse("wallet created")
}

//export createWatchOnlyWallet
func createWatchOnlyWallet(cName, cDataDir, cNet, cPub *C.char) *C.char {
	walletsMtx.Lock()
	defer walletsMtx.Unlock()
	if !initialized {
		return errCResponse("libwallet is not initialized")
	}

	name := goString(cName)
	if _, exists := wallets[name]; exists {
		return errCResponse("wallet already exists with name: %q", name)
	}

	network, err := asset.NetFromString(goString(cNet))
	if err != nil {
		return errCResponse("%v", err)
	}

	logger := logBackend.Logger("[" + name + "]")
	logger.SetLevel(slog.LevelTrace)
	params := asset.CreateWalletParams{
		OpenWalletParams: asset.OpenWalletParams{
			Net:      network,
			DataDir:  goString(cDataDir),
			DbDriver: "bdb",
			Logger:   logger,
		},
	}

	walletCtx, cancel := context.WithCancel(mainCtx)

	w, err := dcr.CreateWatchOnlyWallet(walletCtx, goString(cPub), params)
	if err != nil {
		cancel()
		return errCResponse("%v", err)
	}

	wallets[name] = &wallet{
		Wallet:    w,
		log:       logger,
		ctx:       walletCtx,
		cancelCtx: cancel,
	}
	return successCResponse("wallet created")
}

//export loadWallet
func loadWallet(cName, cDataDir, cNet *C.char) *C.char {
	walletsMtx.Lock()
	defer walletsMtx.Unlock()
	if !initialized {
		return errCResponse("libwallet is not initialized")
	}

	name := goString(cName)
	if _, exists := wallets[name]; exists {
		return successCResponse("wallet already loaded") // not an error, already loaded
	}

	network, err := asset.NetFromString(goString(cNet))
	if err != nil {
		return errCResponse("%v", err)
	}

	logger := logBackend.Logger("[" + name + "]")
	logger.SetLevel(slog.LevelTrace)
	params := asset.OpenWalletParams{
		Net:      network,
		DataDir:  goString(cDataDir),
		DbDriver: "bdb", // use badgerdb for mobile!
		Logger:   logger,
	}

	walletCtx, cancel := context.WithCancel(mainCtx)

	w, err := dcr.LoadWallet(walletCtx, params)
	if err != nil {
		cancel()
		return errCResponse("%v", err)
	}

	if err = w.OpenWallet(walletCtx); err != nil {
		cancel()
		return errCResponse("%v", err)
	}

	wallets[name] = &wallet{
		Wallet:    w,
		log:       logger,
		ctx:       walletCtx,
		cancelCtx: cancel,
	}
	return successCResponse("wallet %q loaded", name)
}

//export walletSeed
func walletSeed(cName, cPass *C.char) *C.char {
	w, ok := loadedWallet(cName)
	if !ok {
		return errCResponse("wallet with name %q not loaded", goString(cName))
	}

	seed, err := w.DecryptSeed([]byte(goString(cPass)))
	if err != nil {
		return errCResponse("w.DecryptSeed error: %v", err)
	}

	return successCResponse("%s", seed)
}

//export walletBalance
func walletBalance(cName *C.char) *C.char {
	w, ok := loadedWallet(cName)
	if !ok {
		return errCResponse("wallet with name %q not loaded", goString(cName))
	}

	const confs = 1
	bals, err := w.AccountBalances(w.ctx, confs)
	if err != nil {
		return errCResponse("w.AccountBalances error: %v", err)
	}

	balMap := map[string]int64{
		"confirmed":   0,
		"unconfirmed": 0,
	}

	for _, bal := range bals {
		balMap["confirmed"] += int64(bal.Spendable)
		balMap["unconfirmed"] += int64(bal.Total) - int64(bal.Spendable)
	}

	balJson, err := json.Marshal(balMap)
	if err != nil {
		return errCResponse("marshal balMap error: %v", err)
	}

	return successCResponse("%s", balJson)
}

//export closeWallet
func closeWallet(cName *C.char) *C.char {
	walletsMtx.Lock()
	defer walletsMtx.Unlock()
	name := goString(cName)
	w, exists := wallets[name]
	if !exists {
		return errCResponse("wallet with name %q does not exist", name)
	}
	w.cancelCtx()
	w.Wait()
	if err := w.CloseWallet(); err != nil {
		return errCResponse("close wallet %q error: %v", name, err.Error())
	}
	delete(wallets, name)
	return successCResponse("wallet %q shutdown", name)
}

//export changePassphrase
func changePassphrase(cName, cOldPass, cNewPass *C.char) *C.char {
	w, ok := loadedWallet(cName)
	if !ok {
		return errCResponse("wallet with name %q not loaded", goString(cName))
	}

	err := w.MainWallet().ChangePrivatePassphrase(w.ctx, []byte(goString(cOldPass)),
		[]byte(goString(cNewPass)))
	if err != nil {
		return errCResponse("w.ChangePrivatePassphrase error: %v", err)
	}

	return successCResponse("passphrase changed")
}
