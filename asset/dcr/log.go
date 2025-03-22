package dcr

import (
	"fmt"
	"sync/atomic"

	"decred.org/dcrwallet/v4/chain"
	"decred.org/dcrwallet/v4/p2p"
	"decred.org/dcrwallet/v4/spv"
	"decred.org/dcrwallet/v4/wallet"
	"decred.org/dcrwallet/v4/wallet/udb"
	"github.com/decred/dcrd/connmgr/v3"
	"github.com/decred/libwallet/assetlog"
	"github.com/decred/slog"
)

// loggingInited will be set when the log rotator has been initialized.
var loggingInited uint32

const LogFileName = "external.log"

// InitGlobalLogging initializes logging in the dcrwallet packages, writing the
// logs to a log file in the specified logDir. If desired, log messages with
// level >= warn can be additionally written to a separate logger. To achieve
// this, pass a non-nil ParentLogger that can be used to create error-only
// loggers.
//
// Logging only has to be initialized once, so an atomic flag is used internally
// to return early on subsequent invocations.
//
// TODO: See if the below precaution is even necessary for dcrwallet. In theory,
// the the rotating file logger must be Close'd at some point, but there are
// concurrency issues with that since btcd and btcwallet have unsupervised
// goroutines still running after shutdown. So we leave the rotator running at
// the risk of losing some logs.
func InitGlobalLogging(externalLogDir string, errorLogger assetlog.ParentLogger, lvl slog.Level) error {
	if !atomic.CompareAndSwapUint32(&loggingInited, 0, 1) {
		return nil
	}

	logSpinner, err := assetlog.NewRotator(externalLogDir, LogFileName)
	if err != nil {
		return fmt.Errorf("error initializing log rotator: %w", err)
	}

	backendLog := slog.NewBackend(logSpinner)

	logger := func(name string) slog.Logger {
		l := backendLog.Logger(name)
		l.SetLevel(lvl)
		if errorLogger != nil {
			l = assetlog.NewLoggerPlus(l, errorLogger.SubLogger(name))
		}
		return l
	}

	// TODO: Do we care about logs from other packages? vsp maybe?
	wallet.UseLogger(logger("WLLT"))
	udb.UseLogger(logger("UDB"))
	chain.UseLogger(logger("CHAIN"))
	spv.UseLogger(logger("SPV"))
	p2p.UseLogger(logger("P2P"))
	connmgr.UseLogger(logger("CONMGR"))

	return nil
}
