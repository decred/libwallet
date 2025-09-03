package dcr

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
)

// DefaultAccountAddresses returns addresses for the default account. Returns
// used and unused addresses up to nUsed and nUnused. No unused addresses are
// returned if nUnused is zero. All used addresses are returned if nUsed is
// zero. index is the first unused index.
func (w *Wallet) DefaultAccountAddresses(ctx context.Context, nUsed, nUnused uint32) (used, unused []string, index uint32, err error) {
	xpub, err := hdkeychain.NewKeyFromString(w.metaData.DefaultAccountXPub, w.chainParams)
	if err != nil {
		return nil, nil, 0, err
	}
	extBranch, err := xpub.Child(0)
	if err != nil {
		return nil, nil, 0, err
	}
	const accountNum = 0
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

const (
	mainnetPrivKeyPrefix = "dprv"
	mainnetPubKeyPrefix  = "dpub"

	simnetPrivKeyPrefix = "sprv"
	simnetPubKeyPrefix  = "spub"

	testnetPrivKeyPrefix = "tprv"
	testnetPubKeyPrefix  = "tpub"
)

// AddrFromExtendedKey returns an address of the chosen type derived from key at
// the chosen path. The key can be a private or public key. They path must be in
// the form n'/n/...
func AddrFromExtendedKey(key, path, addrType string, useChildBIP32Std bool) (string, error) {
	if len(key) < 4 {
		return "", errors.New("key is too short")
	}

	var (
		net *chaincfg.Params
		err error
	)

	switch strings.ToLower(key[:4]) {
	case mainnetPrivKeyPrefix, mainnetPubKeyPrefix:
		net, err = ParseChainParams("mainnet")
	case testnetPrivKeyPrefix, testnetPubKeyPrefix:
		net, err = ParseChainParams("testnet")
	case simnetPrivKeyPrefix, simnetPubKeyPrefix:
		net, err = ParseChainParams("simnet")
	default:
		return "", errors.New("the key is not from a known network")
	}
	if err != nil {
		return "", err
	}

	extKey, err := hdkeychain.NewKeyFromString(key, net)
	if err != nil {
		return "", err
	}
	defer extKey.Zero()

	paths := strings.Split(path, "/")

	for _, p := range paths {
		if len(p) == 0 {
			continue
		}
		nStr := p
		isHardened := p[len(p)-1:] == "'"
		if isHardened {
			nStr = nStr[:len(p)-1]
		}
		n, err := strconv.ParseUint(nStr, 10, 32)
		if err != nil {
			return "", err
		}
		if isHardened {
			n += hdkeychain.HardenedKeyStart
		}
		if useChildBIP32Std {
			extKey, err = extKey.ChildBIP32Std(uint32(n))
		} else {
			extKey, err = extKey.Child(uint32(n))
		}
		if err != nil {
			return "", err
		}
	}

	switch strings.ToLower(addrType) {
	case "p2pkh":
		pkHash := stdaddr.Hash160(extKey.SerializedPubKey())
		addr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(pkHash, net)
		if err != nil {
			return "", err
		}
		return addr.String(), nil
	default:
		return "", fmt.Errorf("unknown address type %v", addrType)
	}
}
