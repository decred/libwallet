package dcr

import (
	"context"
	"errors"

	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
)

// AddressesByAccount handles a getaddressesbyaccount request by returning
// external addresses for an account, or an error if the requested account does
// not exist. Returns used and unused addresses up to nUsed and nUnused. No
// unused addresses are returned if nUnused is zero. All used addresses are
// returned if nUsed is zero. index is the first unused index.
func (w *Wallet) AddressesByAccount(ctx context.Context, account string, nUsed, nUnused uint32) (used, unused []string, index uint32, err error) {
	if account == "imported" {
		addrs, err := w.mainWallet.ImportedAddresses(ctx, account)
		if err != nil {
			return nil, nil, 0, err
		}
		addrStrs := make([]string, 0, len(addrs))
		for i := range addrs {
			if nUsed != 0 && uint32(i) >= nUsed {
				break
			}
			addrStrs = append(addrStrs, addrs[i].String())
		}
		return addrStrs, nil, 0, nil
	}
	accountNum, err := w.mainWallet.AccountNumber(ctx, account)
	if err != nil {
		return nil, nil, 0, err
	}
	xpub, err := w.mainWallet.AccountXpub(ctx, accountNum)
	if err != nil {
		return nil, nil, 0, err
	}
	extBranch, err := xpub.Child(0)
	if err != nil {
		return nil, nil, 0, err
	}
	endExt, _, err := w.mainWallet.BIP0044BranchNextIndexes(ctx, accountNum)
	if err != nil {
		return nil, nil, 0, err
	}
	params := w.mainWallet.ChainParams()
	var totalUsed, totalUnused uint32
	if nUsed != 0 && endExt >= nUsed {
		totalUsed = nUsed
	} else if endExt > 0 {
		// The returned index is unused.
		totalUsed = endExt
	}
	if nUnused != 0 && endExt+nUnused < hdkeychain.HardenedKeyStart {
		totalUnused = nUnused
	}
	appendAddr := func(addrs *[]string, i uint32) error {
		child, err := extBranch.Child(i)
		if errors.Is(err, hdkeychain.ErrInvalidChild) {
			return nil
		}
		if err != nil {
			return err
		}
		pkh := dcrutil.Hash160(child.SerializedPubKey())
		addr, _ := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
			pkh, params)
		*addrs = append(*addrs, addr.String())
		return nil
	}
	used = make([]string, 0, totalUsed)
	for i := uint32(0); i < totalUsed; i++ {
		if err := appendAddr(&used, endExt-1-i); err != nil {
			return nil, nil, 0, err
		}
	}
	unused = make([]string, 0, totalUnused)
	for i := uint32(0); i < totalUnused; i++ {
		if err := appendAddr(&unused, endExt+i); err != nil {
			return nil, nil, 0, err
		}
	}
	return used, unused, endExt, nil
}

// AccountPubkey returns an account's extended pubkey encoded for the network.
func (w *Wallet) AccountPubkey(ctx context.Context, acct string) (string, error) {
	accountN, err := w.mainWallet.AccountNumber(ctx, acct)
	if err != nil {
		return "", err
	}

	xpub, err := w.mainWallet.AccountXpub(ctx, accountN)
	if err != nil {
		return "", err
	}

	return xpub.String(), nil
}
