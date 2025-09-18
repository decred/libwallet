package dcr

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	walleterrors "decred.org/dcrwallet/v4/errors"
	wallettypes "decred.org/dcrwallet/v4/rpc/jsonrpc/types"
	"decred.org/dcrwallet/v4/wallet"
	"github.com/decred/base58"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/crypto/ripemd160"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/txscript/v4/stdscript"
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

// doubleBlake256Cksum returns the first four bytes of BLAKE256(BLAKE256(v)).
func doubleBlake256Cksum(v []byte) []byte {
	first := blake256.Sum256(v)
	second := blake256.Sum256(first[:])
	return second[:4]
}

// hash160 returns RIPEMD160(BLAKE256(v)).
func hash160(v []byte) []byte {
	blake256Hash := blake256.Sum256(v)
	h := ripemd160.New()
	h.Write(blake256Hash[:])
	return h.Sum(nil)
}

// CreateExtendedKey will create an extended key for the chosen network. The
// key can be public or private. The parent key must be a public key.
func CreateExtendedKey(keyHex, parentKeyHex, chainCodeHex, network string, depth uint8, childN uint32, isPrivate bool) (string, error) {
	net, err := ParseChainParams(network)
	if err != nil {
		return "", err
	}
	chainCode, err := hex.DecodeString(chainCodeHex)
	if err != nil {
		return "", err
	}
	if len(chainCode) != 32 {
		return "", fmt.Errorf("expected chain code with length of 32 but got %d", len(chainCode))
	}
	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	if depth > 0 {
		parentKeyB, err := hex.DecodeString(parentKeyHex)
		if err != nil {
			return "", err
		}
		parentKey, err := secp256k1.ParsePubKey(parentKeyB)
		if err != nil {
			return "", err
		}
		parentFP = hash160(parentKey.SerializeCompressed())[:4]
	}
	keyB, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", err
	}
	var ver [4]byte
	if isPrivate {
		if len(keyB) != 32 {
			return "", fmt.Errorf("expected private key with length of 32 but got %d", len(keyB))
		}
		var b [33]byte
		copy(b[1:], keyB)
		keyB = b[:]
		ver = net.HDPrivateKeyID
	} else {
		key, err := secp256k1.ParsePubKey(keyB)
		if err != nil {
			return "", err
		}
		keyB = key.SerializeCompressed()
		ver = net.HDPublicKeyID
	}
	var childNumB [4]byte
	binary.BigEndian.PutUint32(childNumB[:], childN)
	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (4)) ||
	//   child num (4) || chain code (32) || key data (33) || checksum (4)
	const exKeyLen = 4 + 1 + 4 + 4 + 32 + 33
	var extKeyB [exKeyLen]byte
	copy(extKeyB[:], ver[:])
	extKeyB[4] = depth
	copy(extKeyB[4+1:], parentFP[:])
	copy(extKeyB[4+1+4:], childNumB[:])
	copy(extKeyB[4+1+4+4:], chainCode[:])
	copy(extKeyB[4+1+4+4+32:], keyB[:])
	checkSum := doubleBlake256Cksum(extKeyB[:])
	return base58.Encode(append(extKeyB[:], checkSum...)), nil
}

func decodeAddress(s string, params *chaincfg.Params) (stdaddr.Address, error) {
	// Secp256k1 pubkey as a string, handle differently.
	if len(s) == 66 || len(s) == 130 {
		pubKeyBytes, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		pubKeyAddr, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0Raw(
			pubKeyBytes, params)
		if err != nil {
			return nil, err
		}

		return pubKeyAddr, nil
	}

	addr, err := stdaddr.DecodeAddress(s, params)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: decode failed: %#q", s, err)
	}
	return addr, nil
}

// ValidateAddr validates an address.
func (w *Wallet) ValidateAddr(ctx context.Context, addrStr string) (*wallettypes.ValidateAddressResult, error) {
	result := &wallettypes.ValidateAddressResult{}
	addr, err := decodeAddress(addrStr, w.chainParams)
	if err != nil {
		result.Script = stdscript.STNonStandard.String()
		// Use result zero value (IsValid=false).
		return result, nil
	}

	result.Address = addr.String()
	result.IsValid = true
	ver, scr := addr.PaymentScript()
	class, _ := stdscript.ExtractAddrs(ver, scr, w.ChainParams())
	result.Script = class.String()
	if pker, ok := addr.(stdaddr.SerializedPubKeyer); ok {
		result.PubKey = hex.EncodeToString(pker.SerializedPubKey())
		result.PubKeyAddr = addr.String()
	}
	if class == stdscript.STScriptHash {
		result.IsScript = true
	}
	if _, ok := addr.(stdaddr.Hash160er); ok {
		result.IsCompressed = true
	}

	ka, err := w.KnownAddress(ctx, addr)
	if err != nil {
		if errors.Is(err, walleterrors.NotExist) {
			// No additional information available about the address.
			return result, nil
		}
		return nil, err
	}

	// The address lookup was successful which means there is further
	// information about it available and it is "mine".
	result.IsMine = true
	result.Account = ka.AccountName()

	switch ka := ka.(type) {
	case wallet.PubKeyHashAddress:
		pubKey := ka.PubKey()
		result.PubKey = hex.EncodeToString(pubKey)
		pubKeyAddr, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0Raw(pubKey, w.ChainParams())
		if err != nil {
			return nil, err
		}
		result.PubKeyAddr = pubKeyAddr.String()
	case wallet.P2SHAddress:
		version, script := ka.RedeemScript()
		result.Hex = hex.EncodeToString(script)

		class, addrs := stdscript.ExtractAddrs(version, script, w.ChainParams())
		addrStrings := make([]string, len(addrs))
		for i, a := range addrs {
			addrStrings[i] = a.String()
		}
		result.Addresses = addrStrings
		result.Script = class.String()

		// Multi-signature scripts also provide the number of required
		// signatures.
		if class == stdscript.STMultiSig {
			result.SigsRequired = int32(stdscript.DetermineRequiredSigs(version, script))
		}
	}

	if ka, ok := ka.(wallet.BIP0044Address); ok {
		acct, branch, child := ka.Path()
		if ka.AccountKind() != wallet.AccountKindImportedXpub {
			result.AccountN = &acct
		}
		result.Branch = &branch
		result.Index = &child
	}

	return result, nil
}
