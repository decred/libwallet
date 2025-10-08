package dcr

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand"

	wallettypes "decred.org/dcrwallet/v4/rpc/jsonrpc/types"
	"decred.org/dcrwallet/v4/wallet"
	"decred.org/dcrwallet/v4/wallet/txauthor"
	"decred.org/dcrwallet/v4/wallet/txsizes"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/wire"
)

const defaultAccount = "default"

// newTxOut returns a new transaction output with the given parameters.
func newTxOut(amount int64, pkScriptVer uint16, pkScript []byte) *wire.TxOut {
	return &wire.TxOut{
		Value:    amount,
		Version:  pkScriptVer,
		PkScript: pkScript,
	}
}

// signRawTransaction signs the provided transaction.
func (w *Wallet) signRawTransaction(ctx context.Context, baseTx *wire.MsgTx) (*wire.MsgTx, error) {
	// Copy the passed transaction to avoid altering it.
	tx := baseTx.Copy()
	sigErrs, err := w.mainWallet.SignTransaction(ctx, tx, txscript.SigHashAll, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if len(sigErrs) > 0 {
		for _, sigErr := range sigErrs {
			w.log.Errorf("signature error for index %d: %v", sigErr.InputIndex, sigErr.Error)
		}
		return nil, fmt.Errorf("%d signature errors", len(sigErrs))
	}
	return tx, nil
}

type Output struct {
	Address string
	Amount  uint64
}

type Input struct {
	TxID string
	Vout uint32
}

func (in Input) String() string {
	return fmt.Sprintf("%s:%d", in.TxID, in.Vout)
}

var _ txauthor.ChangeSource = (*changeSource)(nil)

type changeSource struct {
	script  []byte
	version uint16
}

func (cs *changeSource) Script() (script []byte, version uint16, err error) {
	return cs.script, cs.version, nil
}

func (cs *changeSource) ScriptSize() int {
	return len(cs.script)
}

// CreateTransaction creates a transaction. The wallet must be unlocked before
// calling if signing. sendAll will send everything to one output. In that
// case the output's amount is ignored.
func (w *Wallet) CreateTransaction(ctx context.Context, outputs []*Output,
	inputs, ignoreInputs []*Input, feeRate uint64, sendAll, sign bool) (signedTx []byte,
	txid *chainhash.Hash, fee uint64, err error) {
	if sendAll && len(outputs) > 1 {
		return nil, nil, 0, errors.New("send all can only be used with one recepient")
	}
	if len(outputs) < 1 {
		return nil, nil, 0, errors.New("no outputs")
	}
	var ignoreCoinIDs = make(map[string]struct{})
	for _, in := range ignoreInputs {
		ignoreCoinIDs[in.String()] = struct{}{}
	}
	var inputSource txauthor.InputSource
	details := new(txauthor.InputDetail)
	addUTXO := func(utxo *wallettypes.ListUnspentResult, coinID string) error {
		amt, err := dcrutil.NewAmount(utxo.Amount)
		if err != nil {
			return err
		}
		details.Amount += amt
		hash, err := chainhash.NewHashFromStr(utxo.TxID)
		if err != nil {
			return err
		}
		prevOut := wire.NewOutPoint(hash, utxo.Vout, utxo.Tree)
		txIn := wire.NewTxIn(prevOut, int64(amt), []byte{})
		details.Inputs = append(details.Inputs, txIn)
		if len(utxo.ScriptPubKey) == 0 {
			return fmt.Errorf("redeem script for input %s not found", coinID)
		}
		script, err := hex.DecodeString(utxo.ScriptPubKey)
		if err != nil {
			return fmt.Errorf("cannot parse redeem script for input %s: %v", coinID, err)
		}
		details.Scripts = append(details.Scripts, script)
		details.RedeemScriptSizes = append(details.RedeemScriptSizes, txsizes.RedeemP2PKHSigScriptSize)
		return nil
	}
	if len(inputs) > 0 {
		// If inputs were specified use only them and all of them.
		unspents, err := w.mainWallet.ListUnspent(ctx, 0, math.MaxInt32, nil, defaultAccount)
		if err != nil {
			return nil, nil, 0, err
		}
		if len(unspents) == 0 {
			return nil, nil, 0, errors.New("insufficient funds. 0 DCR available to spend in default account")
		}
		var coinIDs = make(map[string]struct{})
		for _, in := range inputs {
			coinIDs[in.String()] = struct{}{}
		}
		for coin := range coinIDs {
			if _, has := ignoreCoinIDs[coin]; has {
				return nil, nil, 0, fmt.Errorf("ignored coin %v found in specified inputs", coin)
			}
		}
		for _, utxo := range unspents {
			coinID := fmt.Sprintf("%s:%d", utxo.TxID, utxo.Vout)
			if _, use := coinIDs[coinID]; !use {
				continue
			}
			if _, ignore := ignoreCoinIDs[coinID]; ignore {
				continue
			}
			if !utxo.Spendable {
				return nil, nil, 0, fmt.Errorf("specified input %s is not spendable", coinID)
			}
			if err := addUTXO(utxo, coinID); err != nil {
				return nil, nil, 0, err
			}
			delete(coinIDs, coinID)
		}
		if len(coinIDs) != 0 {
			return nil, nil, 0, errors.New("some utxo were not found in unspents")
		}
		// Ignore the amount and just let it error if it is not enough.
		// We use all specified inputs regardless.
		inputSource = func(dcrutil.Amount) (detail *txauthor.InputDetail, err error) {
			return details, nil
		}
	} else if len(ignoreInputs) > 0 {
		// If we have inputs to ignore, randomize all inputs and ignore
		// those specified.
		unspents, err := w.mainWallet.ListUnspent(ctx, 0, math.MaxInt32, nil, defaultAccount)
		if err != nil {
			return nil, nil, 0, err
		}
		if len(unspents) == 0 {
			return nil, nil, 0, errors.New("insufficient funds. 0 DCR available to spend in default account")
		}
		for i := range unspents {
			j := rand.Intn(i + 1)
			unspents[i], unspents[j] = unspents[j], unspents[i]
		}
		// Let dcrwallet calculate the total amount with fee for us
		// while choosing inputs randomly.
		inputSource = func(target dcrutil.Amount) (detail *txauthor.InputDetail, err error) {
			for _, utxo := range unspents {
				if details.Amount >= target && !sendAll {
					break
				}
				coinID := fmt.Sprintf("%s:%d", utxo.TxID, utxo.Vout)
				if _, ignore := ignoreCoinIDs[coinID]; ignore {
					continue
				}
				if !utxo.Spendable {
					continue
				}
				if err := addUTXO(utxo, coinID); err != nil {
					return nil, err
				}
			}
			return details, nil
		}
	}

	outs := make([]*wire.TxOut, len(outputs))

	for i, out := range outputs {
		addr, err := stdaddr.DecodeAddress(out.Address, w.chainParams)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("invalid address: %s", out.Address)
		}
		payScriptVer, payScript := addr.PaymentScript()
		txOut := newTxOut(int64(out.Amount), payScriptVer, payScript)
		outs[i] = txOut
	}

	const (
		accountNum = 0
		confs      = 1
	)
	var atx *txauthor.AuthoredTx

	if sendAll {
		// Only set the change source in order to force all funds there.
		// OutputSelectionAlgorithm is ignored when the input source is supplied.
		cs := &changeSource{
			script:  outs[0].PkScript,
			version: outs[0].Version,
		}
		atx, err = w.NewUnsignedTransaction(ctx, nil, dcrutil.Amount(feeRate), accountNum, confs,
			wallet.OutputSelectionAlgorithmAll, cs, inputSource)
		if err != nil {
			return nil, nil, 0, err
		}
	} else {
		atx, err = w.NewUnsignedTransaction(ctx, outs, dcrutil.Amount(feeRate), accountNum, confs,
			wallet.OutputSelectionAlgorithmDefault, nil, inputSource)
		if err != nil {
			return nil, nil, 0, err
		}
	}
	fee = uint64(atx.TotalInput)
	for i := range atx.Tx.TxOut {
		fee -= uint64(atx.Tx.TxOut[i].Value)
	}

	if !sign {
		txHash := atx.Tx.TxHash()
		b, err := atx.Tx.Bytes()
		if err != nil {
			return nil, nil, 0, err
		}
		return b, &txHash, fee, nil
	}

	signedMsgTx, err := w.signRawTransaction(ctx, atx.Tx)
	if err != nil {
		return nil, nil, 0, err
	}

	signedTx, err = signedMsgTx.Bytes()
	if err != nil {
		return nil, nil, 0, err
	}

	txHash := signedMsgTx.TxHash()
	return signedTx, &txHash, fee, nil
}

// SendRawTransaction broadcasts the provided transaction to the Decred network.
func (w *Wallet) SendRawTransaction(ctx context.Context, txHex string) (*chainhash.Hash, error) {
	msgBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, fmt.Errorf("unable to decode hex: %v", err)
	}
	msgTx := new(wire.MsgTx)
	if err := msgTx.FromBytes(msgBytes); err != nil {
		return nil, fmt.Errorf("unable to create msgtx from bytes: %v", err)
	}
	w.syncerMtx.RLock()
	defer w.syncerMtx.RUnlock()
	return w.mainWallet.PublishTransaction(ctx, msgTx, w.syncer)
}
