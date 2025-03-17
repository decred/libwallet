package main

import "C"
import (
	"encoding/base64"
	"encoding/json"
	"strconv"

	dcrwallet "decred.org/dcrwallet/v4/wallet"
	"decred.org/dcrwallet/v4/wallet/udb"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
)

//export currentReceiveAddress
func currentReceiveAddress(cName *C.char) *C.char {
	w, ok := loadedWallet(cName)
	if !ok {
		return errCResponse("wallet with name %q is not loaded", goString(cName))
	}

	if !w.allowUnsyncedAddrs {
		synced, _ := w.IsSynced(w.ctx)
		if !synced {
			return errCResponseWithCode(ErrCodeNotSynced, "currentReceiveAddress requested on an unsynced wallet")
		}
	}

	addr, err := w.CurrentAddress(udb.DefaultAccountNum)
	if err != nil {
		return errCResponse("w.CurrentAddress error: %v", err)
	}

	return successCResponse("%s", addr)
}

//export newExternalAddress
func newExternalAddress(cName *C.char) *C.char {
	w, ok := loadedWallet(cName)
	if !ok {
		return errCResponse("wallet with name %q is not loaded", goString(cName))
	}

	if !w.allowUnsyncedAddrs {
		synced, _ := w.IsSynced(w.ctx)
		if !synced {
			return errCResponseWithCode(ErrCodeNotSynced, "newExternalAddress requested on an unsynced wallet")
		}
	}

	_, err := w.NewExternalAddress(w.ctx, udb.DefaultAccountNum)
	if err != nil {
		return errCResponse("w.NewExternalAddress error: %v", err)
	}

	// NewExternalAddress will take the current address before increasing
	// the index. Get the current address after increasing the index.
	addr, err := w.CurrentAddress(udb.DefaultAccountNum)
	if err != nil {
		return errCResponse("w.CurrentAddress error: %v", err)
	}

	return successCResponse("%s", addr)
}

//export signMessage
func signMessage(cName, cMessage, cAddress, cPassword *C.char) *C.char {
	w, ok := loadedWallet(cName)
	if !ok {
		return errCResponse("wallet with name %q is not loaded", goString(cName))
	}

	addr, err := stdaddr.DecodeAddress(goString(cAddress), w.MainWallet().ChainParams())
	if err != nil {
		return errCResponse("unable to decode address: %v", err)
	}

	// Addresses must have an associated secp256k1 private key and therefore
	// must be P2PK or P2PKH (P2SH is not allowed).
	switch addr.(type) {
	case *stdaddr.AddressPubKeyEcdsaSecp256k1V0:
	case *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0:
		// Valid address types, proceed to sign.
	default:
		return errCResponse("invalid address type: must be P2PK or P2PKH")
	}

	if err := w.MainWallet().Unlock(w.ctx, []byte(goString(cPassword)), nil); err != nil {
		return errCResponse("cannot unlock wallet: %v", err)
	}

	sig, err := w.MainWallet().SignMessage(w.ctx, goString(cMessage), addr)
	if err != nil {
		return errCResponse("unable to sign message: %v", err)
	}

	sEnc := base64.StdEncoding.EncodeToString(sig)

	return successCResponse("%s", sEnc)
}

//export verifyMessage
func verifyMessage(cName, cMessage, cAddress, cSig *C.char) *C.char {
	w, ok := loadedWallet(cName)
	if !ok {
		return errCResponse("wallet with name %q is not loaded", goString(cName))
	}

	addr, err := stdaddr.DecodeAddress(goString(cAddress), w.MainWallet().ChainParams())
	if err != nil {
		return errCResponse("unable to decode address: %v", err)
	}

	// Addresses must have an associated secp256k1 private key and therefore
	// must be P2PK or P2PKH (P2SH is not allowed).
	switch addr.(type) {
	case *stdaddr.AddressPubKeyEcdsaSecp256k1V0:
	case *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0:
		// Valid address types, proceed with verification.
	default:
		return errCResponse("invalid address type: must be P2PK or P2PKH")
	}

	sig, err := base64.StdEncoding.DecodeString(goString(cSig))
	if err != nil {
		return errCResponse("unable to decode signature: %v", err)
	}

	ok, err = dcrwallet.VerifyMessage(goString(cMessage), addr, sig, w.MainWallet().ChainParams())
	if err != nil {
		return errCResponse("unable to verify message: %v", err)
	}

	return successCResponse("%v", ok)
}

//export addresses
func addresses(cName, cNUsed, cNUnused *C.char) *C.char {
	w, ok := loadedWallet(cName)
	if !ok {
		return errCResponse("wallet with name %q is not loaded", goString(cName))
	}

	nUsed, err := strconv.ParseUint(goString(cNUsed), 10, 32)
	if err != nil {
		return errCResponse("number of used addresses is not a uint32: %v", err)
	}

	nUnused, err := strconv.ParseUint(goString(cNUnused), 10, 32)
	if err != nil {
		return errCResponse("number of unused addresses is not a uint32: %v", err)
	}

	used, unused, index, err := w.DefaultAccountAddresses(w.ctx, uint32(nUsed), uint32(nUnused))
	if err != nil {
		return errCResponse("w.DefaultAccountAddresses error: %v", err)
	}

	res := &AddressesRes{
		Used:   used,
		Unused: []string{},
		Index:  index,
	}
	synced, _ := w.IsSynced(w.ctx)
	if synced || w.allowUnsyncedAddrs {
		res.Unused = unused
	}

	b, err := json.Marshal(res)
	if err != nil {
		return errCResponse("unable to marshal addresses: %v", err)
	}

	return successCResponse("%s", b)
}

//export defaultPubkey
func defaultPubkey(cName *C.char) *C.char {
	w, ok := loadedWallet(cName)
	if !ok {
		return errCResponse("wallet with name %q is not loaded", goString(cName))
	}

	pubkey, err := w.AccountPubkey(w.ctx, defaultAccount)
	if err != nil {
		return errCResponse("unable to get default pubkey: %v", err)
	}

	return successCResponse("%s", pubkey)
}
