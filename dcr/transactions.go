package dcr

import (
	"bytes"
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
	"github.com/decred/dcrd/blockchain/stake/v5"
	"github.com/decred/dcrd/blockchain/standalone/v2"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrjson/v4"
	"github.com/decred/dcrd/dcrutil/v4"
	dcrdtypes "github.com/decred/dcrd/rpc/jsonrpc/types/v4"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/txscript/v4/stdscript"
	"github.com/decred/dcrd/wire"
)

const (
	defaultAccount = "default"
	// sstxCommitmentString is the string to insert when a verbose
	// transaction output's pkscript type is a ticket commitment.
	sstxCommitmentString = "sstxcommitment"
)

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

// createVinList returns a slice of JSON objects for the inputs of the passed
// transaction.
func createVinList(mtx *wire.MsgTx, isTreasuryEnabled bool) []dcrdtypes.Vin {
	// Treasurybase transactions only have a single txin by definition.
	//
	// NOTE: This check MUST come before the coinbase check because a
	// treasurybase will be identified as a coinbase as well.
	vinList := make([]dcrdtypes.Vin, len(mtx.TxIn))
	if isTreasuryEnabled && standalone.IsTreasuryBase(mtx) {
		txIn := mtx.TxIn[0]
		vinEntry := &vinList[0]
		vinEntry.Treasurybase = true
		vinEntry.Sequence = txIn.Sequence
		vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
		vinEntry.BlockHeight = txIn.BlockHeight
		vinEntry.BlockIndex = txIn.BlockIndex
		return vinList
	}

	// Coinbase transactions only have a single txin by definition.
	if standalone.IsCoinBaseTx(mtx, isTreasuryEnabled) {
		txIn := mtx.TxIn[0]
		vinEntry := &vinList[0]
		vinEntry.Coinbase = hex.EncodeToString(txIn.SignatureScript)
		vinEntry.Sequence = txIn.Sequence
		vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
		vinEntry.BlockHeight = txIn.BlockHeight
		vinEntry.BlockIndex = txIn.BlockIndex
		return vinList
	}

	// Treasury spend transactions only have a single txin by definition.
	if isTreasuryEnabled && stake.IsTSpend(mtx) {
		txIn := mtx.TxIn[0]
		vinEntry := &vinList[0]
		vinEntry.TreasurySpend = hex.EncodeToString(txIn.SignatureScript)
		vinEntry.Sequence = txIn.Sequence
		vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
		vinEntry.BlockHeight = txIn.BlockHeight
		vinEntry.BlockIndex = txIn.BlockIndex
		return vinList
	}

	// Stakebase transactions (votes) have two inputs: a null stake base
	// followed by an input consuming a ticket's stakesubmission.
	isSSGen := stake.IsSSGen(mtx)

	for i, txIn := range mtx.TxIn {
		// Handle only the null input of a stakebase differently.
		if isSSGen && i == 0 {
			vinEntry := &vinList[0]
			vinEntry.Stakebase = hex.EncodeToString(txIn.SignatureScript)
			vinEntry.Sequence = txIn.Sequence
			vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
			vinEntry.BlockHeight = txIn.BlockHeight
			vinEntry.BlockIndex = txIn.BlockIndex
			continue
		}

		// The disassembled string will contain [error] inline
		// if the script doesn't fully parse, so ignore the
		// error here.
		disbuf, _ := txscript.DisasmString(txIn.SignatureScript)

		vinEntry := &vinList[i]
		vinEntry.Txid = txIn.PreviousOutPoint.Hash.String()
		vinEntry.Vout = txIn.PreviousOutPoint.Index
		vinEntry.Tree = txIn.PreviousOutPoint.Tree
		vinEntry.Sequence = txIn.Sequence
		vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
		vinEntry.BlockHeight = txIn.BlockHeight
		vinEntry.BlockIndex = txIn.BlockIndex
		vinEntry.ScriptSig = &dcrdtypes.ScriptSig{
			Asm: disbuf,
			Hex: hex.EncodeToString(txIn.SignatureScript),
		}
	}

	return vinList
}

// createVoutList returns a slice of JSON objects for the outputs of the passed
// transaction.
func createVoutList(mtx *wire.MsgTx, chainParams *chaincfg.Params) ([]dcrdtypes.Vout, error) {

	txType := stake.DetermineTxType(mtx)
	voutList := make([]dcrdtypes.Vout, 0, len(mtx.TxOut))
	for i, v := range mtx.TxOut {
		// The disassembled string will contain [error] inline if the
		// script doesn't fully parse, so ignore the error here.
		disbuf, _ := txscript.DisasmString(v.PkScript)

		// Attempt to extract addresses from the public key script.  In
		// the case of stake submission transactions, the odd outputs
		// contain a commitment address, so detect that case
		// accordingly.
		var addrs []stdaddr.Address
		var scriptType string
		var reqSigs uint16
		var commitAmt *dcrutil.Amount
		if txType == stake.TxTypeSStx && (i%2 != 0) {
			scriptType = sstxCommitmentString
			addr, err := stake.AddrFromSStxPkScrCommitment(v.PkScript,
				chainParams)
			if err != nil {
				return nil, fmt.Errorf("failed to decode ticket "+
					"commitment addr output for tx hash "+
					"%v, output idx %v", mtx.TxHash(), i)
			} else {
				addrs = []stdaddr.Address{addr}
			}
			amt, err := stake.AmountFromSStxPkScrCommitment(v.PkScript)
			if err != nil {
				return nil, fmt.Errorf("failed to decode ticket "+
					"commitment amt output for tx hash %v"+
					", output idx %v", mtx.TxHash(), i)
			} else {
				commitAmt = &amt
			}
		} else {
			// Attempt to extract known addresses associated with the script.
			var st stdscript.ScriptType
			st, addrs = stdscript.ExtractAddrs(v.Version, v.PkScript, chainParams)
			scriptType = st.String()

			// Determine the number of required signatures for known standard
			// dcrdtypes.
			reqSigs = stdscript.DetermineRequiredSigs(v.Version, v.PkScript)
		}

		encodedAddrs := make([]string, len(addrs))
		for j, addr := range addrs {
			encodedAddr := addr.String()
			encodedAddrs[j] = encodedAddr
		}

		var vout dcrdtypes.Vout
		voutSPK := &vout.ScriptPubKey
		vout.N = uint32(i)
		vout.Value = dcrutil.Amount(v.Value).ToCoin()
		vout.Version = v.Version
		voutSPK.Addresses = encodedAddrs
		voutSPK.Asm = disbuf
		voutSPK.Hex = hex.EncodeToString(v.PkScript)
		voutSPK.Type = scriptType
		voutSPK.ReqSigs = int32(reqSigs)
		if commitAmt != nil {
			voutSPK.CommitAmt = dcrjson.Float64(commitAmt.ToCoin())
		}
		voutSPK.Version = v.Version

		voutList = append(voutList, vout)
	}

	return voutList, nil
}

// DecodeTx decodes a transaction from its hex.
func (w *Wallet) DecodeTx(hexStr string) (*dcrdtypes.TxRawDecodeResult, error) {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	serializedTx, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	var mtx wire.MsgTx
	err = mtx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		return nil, err
	}

	voutList, err := createVoutList(&mtx, w.chainParams)
	if err != nil {
		return nil, err
	}

	isTreasuryEnabled := true

	// Create and return the result.
	return &dcrdtypes.TxRawDecodeResult{
		Txid:     mtx.TxHash().String(),
		Version:  int32(mtx.Version),
		Locktime: mtx.LockTime,
		Expiry:   mtx.Expiry,
		Vin:      createVinList(&mtx, isTreasuryEnabled),
		Vout:     voutList,
	}, nil
}

// GetTxn returns the hex representation of the full transaction for the tx.
// Transactions that do not concern the wallet will not be found.
func (w *Wallet) GetTxn(ctx context.Context, txHashes []*chainhash.Hash) (txHexes []string, err error) {
	txn, _, err := w.mainWallet.GetTransactionsByHashes(ctx, txHashes)
	if err != nil {
		return nil, err
	}
	if len(txn) != len(txHashes) {
		return nil, errors.New("could not get all txn")
	}
	txHexes = make([]string, len(txn))
	for i, tx := range txn {
		txB, err := tx.Bytes()
		if err != nil {
			return nil, err
		}
		txHexes[i] = hex.EncodeToString(txB)
	}
	return txHexes, nil
}

// AddSigs adds signatures to a tx. The number of signature scripts should
// match the number of tx inputs. Blank strings may be used to skip inputs.
func (w *Wallet) AddSigs(hexStr string, sigScripts []string) (signedTxHex string, err error) {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	serializedTx, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	var mtx wire.MsgTx
	err = mtx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		return "", err
	}
	if len(mtx.TxIn) != len(sigScripts) {
		return "", errors.New("number of inputs and signatures differ")
	}
	for i := 0; i < len(mtx.TxIn); i++ {
		if len(sigScripts[i]) == 0 {
			continue
		}
		sig, err := hex.DecodeString(sigScripts[i])
		if err != nil {
			return "", err
		}
		mtx.TxIn[i].SignatureScript = sig
	}
	mtx.SerType = wire.TxSerializeFull
	b, err := mtx.Bytes()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
