package main

import "C"
import (
	"encoding/json"
	"strconv"
	"strings"

	"decred.org/dcrwallet/v4/spv"
	dcrwallet "decred.org/dcrwallet/v4/wallet"
)

//export syncWallet
func syncWallet(cName, cPeers *C.char) *C.char {
	w, exists := loadedWallet(cName)
	if !exists {
		return errCResponse("wallet with name %q does not exist", goString(cName))
	}
	var peers []string
	for _, p := range strings.Split(goString(cPeers), ",") {
		if p = strings.TrimSpace(p); p != "" {
			peers = append(peers, p)
		}
	}
	ntfns := &spv.Notifications{
		Synced: func(sync bool) {
			w.syncStatusMtx.Lock()
			w.syncStatusCode = SSCComplete
			w.syncStatusMtx.Unlock()
			w.log.Debug("Sync completed.")
		},
		PeerConnected: func(peerCount int32, addr string) {
			w.syncStatusMtx.Lock()
			w.numPeers = int(peerCount)
			w.syncStatusMtx.Unlock()
			w.log.Debugf("Connected to peer at %s. %d total peers.", addr, peerCount)
		},
		PeerDisconnected: func(peerCount int32, addr string) {
			w.syncStatusMtx.Lock()
			w.numPeers = int(peerCount)
			w.syncStatusMtx.Unlock()
			w.log.Debugf("Disconnected from peer at %s. %d total peers.", addr, peerCount)
		},
		FetchMissingCFiltersStarted: func() {
			w.syncStatusMtx.Lock()
			if w.rescanning {
				w.syncStatusMtx.Unlock()
				return
			}
			w.syncStatusCode = SSCFetchingCFilters
			w.syncStatusMtx.Unlock()
			w.log.Debug("Fetching missing cfilters started.")
		},
		FetchMissingCFiltersProgress: func(startCFiltersHeight, endCFiltersHeight int32) {
			w.syncStatusMtx.Lock()
			w.cfiltersHeight = int(endCFiltersHeight)
			w.syncStatusMtx.Unlock()
			w.log.Debugf("Fetching cfilters from %d to %d.", startCFiltersHeight, endCFiltersHeight)
		},
		FetchMissingCFiltersFinished: func() {
			w.syncStatusMtx.Lock()
			w.cfiltersHeight = w.targetHeight
			w.syncStatusMtx.Unlock()
			w.log.Debug("Finished fetching missing cfilters.")
		},
		FetchHeadersStarted: func() {
			w.syncStatusMtx.Lock()
			if w.rescanning {
				w.syncStatusMtx.Unlock()
				return
			}
			w.syncStatusCode = SSCFetchingHeaders
			w.syncStatusMtx.Unlock()
			w.log.Debug("Fetching headers started.")
		},
		FetchHeadersProgress: func(lastHeaderHeight int32, lastHeaderTime int64) {
			w.syncStatusMtx.Lock()
			w.headersHeight = int(lastHeaderHeight)
			w.syncStatusMtx.Unlock()
			w.log.Debugf("Fetching headers to %d.", lastHeaderHeight)
		},
		FetchHeadersFinished: func() {
			w.syncStatusMtx.Lock()
			w.headersHeight = w.targetHeight
			w.syncStatusMtx.Unlock()
			w.log.Debug("Fetching headers finished.")
		},
		DiscoverAddressesStarted: func() {
			w.syncStatusMtx.Lock()
			if w.rescanning {
				w.syncStatusMtx.Unlock()
				return
			}
			w.syncStatusCode = SSCDiscoveringAddrs
			w.syncStatusMtx.Unlock()
			w.log.Debug("Discover addresses started.")
		},
		DiscoverAddressesFinished: func() {
			w.log.Debug("Discover addresses finished.")
		},
		RescanStarted: func() {
			w.syncStatusMtx.Lock()
			if w.rescanning {
				w.syncStatusMtx.Unlock()
				return
			}
			w.syncStatusCode = SSCRescanning
			w.syncStatusMtx.Unlock()
			w.log.Debug("Rescan started.")
		},
		RescanProgress: func(rescannedThrough int32) {
			w.syncStatusMtx.Lock()
			w.rescanHeight = int(rescannedThrough)
			w.syncStatusMtx.Unlock()
			w.log.Debugf("Rescanned through block %d.", rescannedThrough)
		},
		RescanFinished: func() {
			w.syncStatusMtx.Lock()
			w.rescanHeight = w.targetHeight
			w.syncStatusMtx.Unlock()
			w.log.Debug("Rescan finished.")
		},
	}
	if err := w.StartSync(w.ctx, ntfns, peers...); err != nil {
		return errCResponse("%v", err)
	}
	return successCResponse("sync started")
}

//export syncWalletStatus
func syncWalletStatus(cName *C.char) *C.char {
	w, exists := loadedWallet(cName)
	if !exists {
		return errCResponse("wallet with name %q does not exist", goString(cName))
	}

	w.syncStatusMtx.RLock()
	var ssc, cfh, hh, rh, np = w.syncStatusCode, w.cfiltersHeight, w.headersHeight, w.rescanHeight, w.numPeers
	w.syncStatusMtx.RUnlock()

	// Sometimes it appears we miss a notification during start up. This is
	// a bandaid to put us as synced in that case.
	//
	// TODO: Figure out why we would miss a notification.
	synced, targetHeight := w.IsSynced(w.ctx)
	w.syncStatusMtx.Lock()
	if ssc != SSCComplete && synced && !w.rescanning {
		ssc = SSCComplete
		w.syncStatusCode = ssc
	}
	w.syncStatusMtx.Unlock()

	ss := &SyncStatusRes{
		SyncStatusCode: int(ssc),
		SyncStatus:     ssc.String(),
		TargetHeight:   int(targetHeight),
		NumPeers:       np,
	}
	switch ssc {
	case SSCFetchingCFilters:
		ss.CFiltersHeight = cfh
	case SSCFetchingHeaders:
		ss.HeadersHeight = hh
	case SSCRescanning:
		ss.RescanHeight = rh
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return errCResponse("unable to marshal sync status result: %v", err)
	}
	return successCResponse("%s", b)
}

//export rescanFromHeight
func rescanFromHeight(cName, cHeight *C.char) *C.char {
	height, err := strconv.ParseUint(goString(cHeight), 10, 32)
	if err != nil {
		return errCResponse("height is not an uint32: %v", err)
	}
	name := goString(cName)
	w, exists := loadedWallet(cName)
	if !exists {
		return errCResponse("wallet with name %q does not exist", name)
	}
	synced, _ := w.IsSynced(w.ctx)
	if !synced {
		return errCResponseWithCode(ErrCodeNotSynced, "rescanFromHeight requested on an unsynced wallet")
	}
	w.syncStatusMtx.Lock()
	if w.rescanning {
		w.syncStatusMtx.Unlock()
		return errCResponse("wallet %q already rescanning", name)
	}
	w.syncStatusCode = SSCRescanning
	w.rescanning = true
	w.rescanHeight = int(height)
	w.syncStatusMtx.Unlock()
	w.Add(1)
	go func() {
		defer func() {
			w.syncStatusMtx.Lock()
			w.syncStatusCode = SSCComplete
			w.rescanning = false
			w.syncStatusMtx.Unlock()
			w.Done()
		}()
		prog := make(chan dcrwallet.RescanProgress)
		go func() {
			w.RescanProgressFromHeight(w.ctx, int32(height), prog)
		}()
		for {
			select {
			case p, open := <-prog:
				if !open {
					return
				}
				if p.Err != nil {
					log.Errorf("rescan wallet %q error: %v", name, err)
					return
				}
				w.syncStatusMtx.Lock()
				w.rescanHeight = int(p.ScannedThrough)
				w.syncStatusMtx.Unlock()
			case <-w.ctx.Done():
				return
			}
		}
	}()
	return successCResponse("rescan from height %d for wallet %q started", height, name)
}

//export birthState
func birthState(cName *C.char) *C.char {
	w, ok := loadedWallet(cName)
	if !ok {
		return errCResponse("wallet with name %q is not loaded", goString(cName))
	}

	bs, err := w.MainWallet().BirthState(w.ctx)
	if err != nil {
		return errCResponse("wallet.BirthState error: %v", err)
	}
	if bs == nil {
		return errCResponse("birth state is nil for wallet %q", goString(cName))
	}

	bsRes := &BirthdayState{
		Hash:          bs.Hash.String(),
		Height:        bs.Height,
		Time:          bs.Time.Unix(),
		SetFromHeight: bs.SetFromHeight,
		SetFromTime:   bs.SetFromTime,
	}
	b, err := json.Marshal(bsRes)
	if err != nil {
		return errCResponse("unable to marshal birth state result: %v", err)
	}
	return successCResponse("%s", b)
}
