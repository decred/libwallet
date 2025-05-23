package main

import "C"
import (
	"encoding/json"
	"fmt"

	wallettypes "decred.org/dcrwallet/v4/rpc/jsonrpc/types"
)

const (
	// ErrCodeNotSynced is returned when the wallet must be synced to perform an
	// action but is not.
	ErrCodeNotSynced = 1
)

// CResponse is used for all returns when using the cgo libwallet. Payload only
// populated if no error. Error only populated if error. ErrorCode may be
// populated if an error needs special handling.
type CResponse struct {
	Payload   string `json:"payload,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorCode int    `json:"errorcode,omitempty"`
}

// errCResponse will return an error to the consumer, and log it if possible.
func errCResponse(errStr string, args ...any) *C.char {
	s := fmt.Sprintf(errStr, args...)
	b, err := json.Marshal(CResponse{Error: s})
	if err != nil {
		panic(err)
	}
	logMtx.RLock()
	if log != nil {
		log.Errorf("returning error to consumer: %v", s)
	}
	logMtx.RUnlock()
	return cString(string(b))
}

// errCResponseWithCode will return an error to the consumer, and log it if possible.
func errCResponseWithCode(errCode int, errStr string, args ...any) *C.char {
	s := fmt.Sprintf(errStr, args...)
	b, err := json.Marshal(CResponse{Error: s, ErrorCode: errCode})
	if err != nil {
		panic(err)
	}
	logMtx.RLock()
	if log != nil {
		log.Errorf("returning error with error code %d to consumer: %v", errCode, s)
	}
	logMtx.RUnlock()
	return cString(string(b))
}

// successCResponse will return a payload the consumer, and log it if possible.
func successCResponse(val string, args ...any) *C.char {
	s := fmt.Sprintf(val, args...)
	b, err := json.Marshal(CResponse{Payload: s})
	if err != nil {
		panic(err)
	}
	logMtx.RLock()
	if log != nil {
		log.Tracef("returning payload to consumer: %v", s)
	}
	logMtx.RUnlock()
	return cString(string(b))
}

type SyncStatusCode int

const (
	SSCNotStarted SyncStatusCode = iota
	SSCFetchingCFilters
	SSCFetchingHeaders
	SSCDiscoveringAddrs
	SSCRescanning
	SSCComplete
)

func (ssc SyncStatusCode) String() string {
	return [...]string{"not started", "fetching cfilters", "fetching headers",
		"discovering addresses", "rescanning", "sync complete"}[ssc]
}

type SyncStatusRes struct {
	SyncStatusCode int    `json:"syncstatuscode"`
	SyncStatus     string `json:"syncstatus"`
	TargetHeight   int    `json:"targetheight"`
	NumPeers       int    `json:"numpeers"`
	CFiltersHeight int    `json:"cfiltersheight,omitempty"`
	HeadersHeight  int    `json:"headersheight,omitempty"`
	RescanHeight   int    `json:"rescanheight,omitempty"`
}

type Input struct {
	TxID string `json:"txid"`
	Vout int    `json:"vout"`
}

type Output struct {
	Address string `json:"address"`
	Amount  int    `json:"amount"`
}

type CreateSignedTxReq struct {
	Outputs      []Output `json:"outputs"`
	Inputs       []Input  `json:"inputs"`
	IgnoreInputs []Input  `json:"ignoreinputs"`
	FeeRate      int      `json:"feerate"`
	SendAll      bool     `json:"sendall"`
	Password     string   `json:"password"`
}

type CreateSignedTxRes struct {
	SignedHex string `json:"signedhex"`
	Txid      string `json:"txid"`
	Fee       int    `json:"fee"`
}

type ListUnspentRes struct {
	*wallettypes.ListUnspentResult
	IsChange bool `json:"ischange"`
}

type BestBlockRes struct {
	Hash   string `json:"hash"`
	Height int    `json:"height"`
}

type ListTransactionRes struct {
	Address       string   `json:"address,omitempty"`
	Amount        float64  `json:"amount"`
	Category      string   `json:"category"`
	Confirmations int64    `json:"confirmations"`
	Height        int64    `json:"height"`
	Fee           *float64 `json:"fee,omitempty"`
	Time          int64    `json:"time"`
	TxID          string   `json:"txid"`
	Vout          uint32   `json:"vout"`
}

type BirthdayState struct {
	Hash          string `json:"hash"`
	Height        uint32 `json:"height"`
	Time          int64  `json:"time"`
	SetFromHeight bool   `json:"setfromheight"`
	SetFromTime   bool   `json:"setfromtime"`
}

type AddressesRes struct {
	Used   []string `json:"used"`
	Unused []string `json:"unused"`
	Index  uint32   `json:"index"`
}

type Config struct {
	Name string `json:"name"`
	// Allow getting unused addresses when not synced.
	AllowUnsyncedAddrs bool   `json:"unsyncedaddrs"`
	Net                string `json:"net"`
	DataDir            string `json:"datadir"`
	// Only needed during creation.
	Pass     string `json:"pass"`
	Mnemonic string `json:"mnemonic"`
	// If the wallet existed before but the db was deleted to reduce
	// storage, restore from the local encrypted seed using the provided
	// password. Also works for watching only wallets with no password.
	UseLocalSeed bool `json:"uselocalseed"`
	// Only needed during watching only creation.
	PubKey string `json:"pubkey"`
}
