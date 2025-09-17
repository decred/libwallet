package main

import "C"
import (
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"

	dcrwallet "decred.org/dcrwallet/v4/wallet"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/libwallet/dcr"
)

const defaultAccount = "default"

//export createTransaction
func createTransaction(cName, cCreateTxJSONReq *C.char) *C.char {
	w, exists := loadedWallet(cName)
	if !exists {
		return errCResponse("wallet with name %q does not exist", goString(cName))
	}
	signSendJSONReq := goString(cCreateTxJSONReq)
	var req CreateTxReq
	if err := json.Unmarshal([]byte(signSendJSONReq), &req); err != nil {
		return errCResponse("malformed sign send request: %v", err)
	}

	outputs := make([]*dcr.Output, len(req.Outputs))
	for i, out := range req.Outputs {
		o := &dcr.Output{
			Address: out.Address,
			Amount:  uint64(out.Amount),
		}
		outputs[i] = o
	}

	inputs := make([]*dcr.Input, len(req.Inputs))
	for i, in := range req.Inputs {
		o := &dcr.Input{
			TxID: in.TxID,
			Vout: uint32(in.Vout),
		}
		inputs[i] = o
	}

	ignoreInputs := make([]*dcr.Input, len(req.IgnoreInputs))
	for i, in := range req.IgnoreInputs {
		o := &dcr.Input{
			TxID: in.TxID,
			Vout: uint32(in.Vout),
		}
		ignoreInputs[i] = o
	}

	if req.Sign {
		if err := w.MainWallet().Unlock(w.ctx, []byte(req.Password), nil); err != nil {
			return errCResponse("cannot unlock wallet: %v", err)
		}
		defer w.MainWallet().Lock()
	}

	txBytes, txhash, fee, err := w.CreateTransaction(w.ctx, outputs, inputs, ignoreInputs, uint64(req.FeeRate), req.SendAll, req.Sign)
	if err != nil {
		return errCResponse("unable to sign send transaction: %v", err)
	}
	res := &CreateTxRes{
		Hex:  hex.EncodeToString(txBytes),
		Txid: txhash.String(),
		Fee:  int(fee),
	}

	b, err := json.Marshal(res)
	if err != nil {
		return errCResponse("unable to marshal sign send transaction result: %v", err)
	}
	return successCResponse("%s", b)
}

//export sendRawTransaction
func sendRawTransaction(cName, cTxHex *C.char) *C.char {
	w, exists := loadedWallet(cName)
	if !exists {
		return errCResponse("wallet with name %q does not exist", goString(cName))
	}
	txHash, err := w.SendRawTransaction(w.ctx, goString(cTxHex))
	if err != nil {
		return errCResponse("unable to sign send transaction: %v", err)
	}
	return successCResponse("%s", txHash)
}

//export listUnspents
func listUnspents(cName *C.char) *C.char {
	w, exists := loadedWallet(cName)
	if !exists {
		return errCResponse("wallet with name %q does not exist", goString(cName))
	}
	res, err := w.MainWallet().ListUnspent(w.ctx, 1, math.MaxInt32, nil, defaultAccount)
	if err != nil {
		return errCResponse("unable to get unspents: %v", err)
	}
	// Add is change to results.
	unspentRes := make([]ListUnspentRes, len(res))
	for i, unspent := range res {
		addr, err := stdaddr.DecodeAddress(unspent.Address, w.MainWallet().ChainParams())
		if err != nil {
			return errCResponse("unable to decode address: %v", err)
		}

		ka, err := w.MainWallet().KnownAddress(w.ctx, addr)
		if err != nil {
			return errCResponse("unspent address is not known: %v", err)
		}

		isChange := false
		if ka, ok := ka.(dcrwallet.BIP0044Address); ok {
			_, branch, _ := ka.Path()
			isChange = branch == 1
		}
		unspentRes[i] = ListUnspentRes{
			ListUnspentResult: unspent,
			IsChange:          isChange,
		}
	}
	b, err := json.Marshal(unspentRes)
	if err != nil {
		return errCResponse("unable to marshal list unspents result: %v", err)
	}
	return successCResponse("%s", b)
}

//export estimateFee
func estimateFee(cName, cNBlocks *C.char) *C.char {
	w, exists := loadedWallet(cName)
	if !exists {
		return errCResponse("wallet with name %q does not exist", goString(cName))
	}
	nBlocks, err := strconv.ParseUint(goString(cNBlocks), 10, 64)
	if err != nil {
		return errCResponse("number of blocks is not a uint64: %v", err)
	}
	txFee, err := w.FetchFeeFromOracle(w.ctx, nBlocks)
	if err != nil {
		return errCResponse("unable to get fee from oracle: %v", err)
	}
	return successCResponse("%d", uint64(txFee*1e8))
}

//export listTransactions
func listTransactions(cName, cFrom, cCount *C.char) *C.char {
	w, exists := loadedWallet(cName)
	if !exists {
		return errCResponse("wallet with name %q does not exist", goString(cName))
	}
	from, err := strconv.ParseInt(goString(cFrom), 10, 32)
	if err != nil {
		return errCResponse("from is not an int: %v", err)
	}
	count, err := strconv.ParseInt(goString(cCount), 10, 32)
	if err != nil {
		return errCResponse("count is not an int: %v", err)
	}
	res, err := w.MainWallet().ListTransactions(w.ctx, int(from), int(count))
	if err != nil {
		return errCResponse("unable to get transactions: %v", err)
	}
	_, blockHeight := w.MainWallet().MainChainTip(w.ctx)
	ltRes := make([]*ListTransactionRes, len(res))
	for i, ltw := range res {
		// Use earliest of receive time or block time if the transaction is mined.
		receiveTime := ltw.TimeReceived
		if ltw.BlockTime != 0 && ltw.BlockTime < ltw.TimeReceived {
			receiveTime = ltw.BlockTime
		}

		var height int64
		if ltw.Confirmations > 0 {
			height = int64(blockHeight) - ltw.Confirmations + 1
		}

		lt := &ListTransactionRes{
			Address:       ltw.Address,
			Amount:        ltw.Amount,
			Category:      ltw.Category,
			Confirmations: ltw.Confirmations,
			Height:        height,
			Fee:           ltw.Fee,
			Time:          receiveTime,
			TxID:          ltw.TxID,
			Vout:          ltw.Vout,
		}
		ltRes[i] = lt
	}
	b, err := json.Marshal(ltRes)
	if err != nil {
		return errCResponse("unable to marshal list transactions result: %v", err)
	}
	return successCResponse("%s", b)
}

//export bestBlock
func bestBlock(cName *C.char) *C.char {
	w, exists := loadedWallet(cName)
	if !exists {
		return errCResponse("wallet with name %q does not exist", goString(cName))
	}
	blockHash, blockHeight := w.MainWallet().MainChainTip(w.ctx)
	res := &BestBlockRes{
		Hash:   blockHash.String(),
		Height: int(blockHeight),
	}
	b, err := json.Marshal(res)
	if err != nil {
		return errCResponse("unable to marshal best block result: %v", err)
	}
	return successCResponse("%s", b)
}

//export decodeTx
func decodeTx(cName, cTxHex *C.char) *C.char {
	w, exists := loadedWallet(cName)
	if !exists {
		return errCResponse("wallet with name %q does not exist", goString(cName))
	}
	decoded, err := w.DecodeTx(goString(cTxHex))
	if err != nil {
		return errCResponse("unable to decode tx: %v", err)
	}
	b, err := json.Marshal(decoded)
	if err != nil {
		return errCResponse("unable to marshal decoded tx: %v", err)
	}
	return successCResponse("%s", b)
}

//export getTxn
func getTxn(cName, cHashes *C.char) *C.char {
	w, exists := loadedWallet(cName)
	if !exists {
		return errCResponse("wallet with name %q does not exist", goString(cName))
	}
	var txIDs []string
	if err := json.Unmarshal([]byte(goString(cHashes)), &txIDs); err != nil {
		return errCResponse("unable to unmarshal hashes: %v", err)
	}
	txHashes := make([]*chainhash.Hash, len(txIDs))
	for i, txID := range txIDs {
		txHash, err := chainhash.NewHashFromStr(txID)
		if err != nil {
			return errCResponse("unable to create tx hash: %v", err)
		}
		txHashes[i] = txHash
	}
	hexes, err := w.GetTxn(w.ctx, txHashes)
	if err != nil {
		return errCResponse("unable to get txn: %v", err)
	}
	b, err := json.Marshal(hexes)
	if err != nil {
		return errCResponse("unable to marshal txn: %v", err)
	}
	return successCResponse("%s", b)
}
