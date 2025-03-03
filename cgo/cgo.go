// A pacakge that exports Decred wallet functionalities as go code that can be
// compiled into a c-shared libary. Must be a main package, with an empty main
// function. And functions to be exported must have an "//export {fnName}"
// comment.
//
// Build cmd: go build -buildmode=c-archive -o {path_to_generated_library} ./cgo
// E.g. go build -buildmode=c-archive -o ./build/libdcrwallet.a ./cgo.

package main

import "C"
import (
	"context"
	"runtime"
	"sync"

	"github.com/decred/libwallet/asset/dcr"
	"github.com/decred/libwallet/assetlog"
	"github.com/decred/slog"
)

type globalWallet struct {
	ctx       context.Context
	cancelCtx context.CancelFunc
	wg        sync.WaitGroup

	logBackend *parentLogger
	log        slog.Logger

	wallet *wallet
}

var (
	gwMtx sync.RWMutex
	gw    *globalWallet
)

//export initialize
func initialize(cLogDir *C.char) *C.char {
	gwMtx.Lock()
	defer gwMtx.Unlock()
	if gw != nil {
		return errCResponse("duplicate initialization")
	}

	logDir := goString(cLogDir)
	logSpinner, err := assetlog.NewRotator(logDir, "dcrwallet.log")
	if err != nil {
		return errCResponse("error initializing log rotator: %v", err)
	}

	logBackend := newParentLogger(logSpinner)
	err = dcr.InitGlobalLogging(logDir, logBackend)
	if err != nil {
		return errCResponse("error initializing logger for external pkgs: %v", err)
	}

	log := logBackend.SubLogger("[APP]")
	log.SetLevel(slog.LevelTrace)

	ctx, cancelCtx := context.WithCancel(context.Background())

	gw = &globalWallet{
		ctx:        ctx,
		cancelCtx:  cancelCtx,
		logBackend: logBackend,
		log:        log,
	}

	go func() {
		<-ctx.Done()
		runtime.KeepAlive(gw)
		runtime.KeepAlive(&gwMtx)
	}()
	return successCResponse("libwallet cgo initialized")
}

//export shutdown
func shutdown() *C.char {
	gwMtx.Lock()
	defer gwMtx.Unlock()
	if gw == nil {
		return errCResponse("not initialized")
	}
	gw.log.Debug("libwallet cgo shutting down")
	if err := gw.wallet.CloseWallet(); err != nil {
		gw.log.Errorf("close wallet error: %v", err)
	}

	// Stop all remaining background processes and wait for them to stop.
	gw.cancelCtx()
	gw.wg.Wait()

	// Close the logger backend as the last step.
	gw.log.Debug("libwallet cgo shutdown")
	gw.logBackend.Close()

	return successCResponse("libwallet cgo shutdown")
}

func main() {}
