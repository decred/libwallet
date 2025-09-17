package dcr

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/hdkeychain/v3"
)

func TestAddrFromExtendedKey(t *testing.T) {

	tests := []struct {
		name, key, path, addrType, wantAddr string
		useChildBIP32Std                    bool
	}{{
		name:     "ok same result as https://github.com/decred/dcrd/blob/master/hdkeychain/example_test.go",
		key:      "dprv3hCznBesA6jBushjx7y9NrfheE4ZshnaKYtsoLXefmLPzrXgEiXkdRMD6UngnmBYZzgNhdEd4K3PidxcaCiR6HC9hmpj8FcrP4Cv7zBwELA",
		path:     "0'/1/0",
		addrType: "p2pkh",
		wantAddr: "DsoTyktAyEDkYpgKSex6zx5rrkFDi2gAsHr",
	}, {
		name:     "ok also same result as https://github.com/decred/dcrd/blob/master/hdkeychain/example_test.go",
		key:      "dprv3hCznBesA6jBushjx7y9NrfheE4ZshnaKYtsoLXefmLPzrXgEiXkdRMD6UngnmBYZzgNhdEd4K3PidxcaCiR6HC9hmpj8FcrP4Cv7zBwELA",
		path:     "0'/0/10",
		addrType: "p2pkh",
		wantAddr: "DshMmJ3bfvMDdk1mkXRD3x5xDuPwSxoYGfi",
	}, {
		name:     "ok account pubkey from above",
		key:      "dpubZBcpPfFZ9PGZdqW64aazy29PVfYHXSSK4VzsR6XUu4XUsXcukg1HMiSyvCbLYhxFTGa9ai9awzJhQiZCNnLwEqkkSLmLDLEiomgsRZUt4ei",
		path:     "0/10",
		addrType: "p2pkh",
		wantAddr: "DshMmJ3bfvMDdk1mkXRD3x5xDuPwSxoYGfi",
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addr, err := AddrFromExtendedKey(test.key, test.path, test.addrType, test.useChildBIP32Std)
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			if addr != test.wantAddr {
				t.Fatalf("wanted addr %v but got %v", test.wantAddr, addr)
			}
		})
	}
}

func TestCreateExtendedKey(t *testing.T) {

	tests := []struct {
		name, keyHex, parentKeyHex, chainCodeHex, network, wantKey string
		depth                                                      uint8
		childN                                                     uint32
		isPrivate                                                  bool
	}{{
		name:         "ok key from TestAddrFromExtendedKey",
		keyHex:       "025c2a9436486301dcbdc011548d4ac8b2c0103c0f4af5c860168676ceff4c1979",
		parentKeyHex: "021320df92844ed8a74e217c614bc23a59af1998a1187a214d65cd5610fb7ac82b",
		chainCodeHex: "93d54677306d74dda8e7b47cc06e87053b26609fa763972deb17bad2d0d73c64",
		network:      "mainnet",
		depth:        1,
		childN:       hdkeychain.HardenedKeyStart,
		wantKey:      "dpubZBcpPfFZ9PGZdqW64aazy29PVfYHXSSK4VzsR6XUu4XUsXcukg1HMiSyvCbLYhxFTGa9ai9awzJhQiZCNnLwEqkkSLmLDLEiomgsRZUt4ei",
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := CreateExtendedKey(test.keyHex, test.parentKeyHex, test.chainCodeHex, test.network, test.depth, test.childN, test.isPrivate)
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			if key != test.wantKey {
				t.Fatalf("wanted key %v but got %v", test.wantKey, key)
			}
		})
	}
}

func TestCreateTransaction(t *testing.T) {

	tests := []struct {
		name, keyHex, parentKeyHex, chainCodeHex, network, wantKey string
		depth                                                      uint8
		childN                                                     uint32
		isPrivate                                                  bool
	}{{
		name:         "ok key from TestAddrFromExtendedKey",
		keyHex:       "025c2a9436486301dcbdc011548d4ac8b2c0103c0f4af5c860168676ceff4c1979",
		parentKeyHex: "021320df92844ed8a74e217c614bc23a59af1998a1187a214d65cd5610fb7ac82b",
		chainCodeHex: "93d54677306d74dda8e7b47cc06e87053b26609fa763972deb17bad2d0d73c64",
		network:      "mainnet",
		depth:        1,
		childN:       hdkeychain.HardenedKeyStart,
		wantKey:      "dpubZBcpPfFZ9PGZdqW64aazy29PVfYHXSSK4VzsR6XUu4XUsXcukg1HMiSyvCbLYhxFTGa9ai9awzJhQiZCNnLwEqkkSLmLDLEiomgsRZUt4ei",
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := CreateExtendedKey(test.keyHex, test.parentKeyHex, test.chainCodeHex, test.network, test.depth, test.childN, test.isPrivate)
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			if key != test.wantKey {
				t.Fatalf("wanted key %v but got %v", test.wantKey, key)
			}
		})
	}
}

func TestDecodeTx(t *testing.T) {

	w := &Wallet{
		chainParams: chaincfg.MainNetParams(),
	}

	tests := []struct {
		name, hex string
	}{{
		name: "ok normal tx",
		hex:  "0100000004ff42e8491fb20a667ca0a1b364f6bfc016d7122c048bb4f6cc30fb0a46ea87052000000000ffffffff541b3cd370aca98ab4fb6cc729030512ced1bc5e62bc47d2c78b11497044d4211600000000ffffffff7a6c40a68680f70cb9d5da6508a453351396b24a612c24dbc2ff42ca8e8373642d00000000ffffffffb2fbcd201eb5af94e29999a1b32a3b9e8744259d46e55127259abd4137470d732900000000ffffffff081c2472050000000000001976a914ccf79107d1f818d912826a75773f8c9c77884c8c88ac8db557a30100000000001976a914af2205774323a5f0defb6e87ad99247f2600cf4d88acb94da0a30100000000001976a9144ffc3676a46d9fc09cd64fc48181a9ce4e2595e988ac7273bfe80200000000001976a91442b5f8d8fedb0d298001e6cbbbd8866881e8f29188ac000000000400000000001976a91423649fddd9e359f656951fa7617da274014ad9a788ac000000000400000000001976a91474f356aa9a92c979f65530c509de6a4a101dd8de88ac000000000400000000001976a914847bf10d5532c736ec5766a993d619e943349c1888ac000000000400000000001976a914e36c190707b4c3fef35d9747d2d3de55f96c8e7288ac0000000000000000049b57a0a30500000054520f000b0000006a4730440220187bc7151512a24ae6cfcdeab70d1ce1c162817896f7ef1bd0c6511d70b201a002204f1bd145f1451a8a083a34d011c83f17d538416c641e081b540b02a6b1710af50121038ed5b3762d01ee650693915e51fa4717f02bf37aa14c6ff466925913d5397778fe2d7205040000009d4f0f000a0000006b483045022100c1d67e740fac39a294ee675c34ad5012a8702ae3f8b9a5142aaeeb5cbf1b664d022044d90ba48935106339d08e38d4f5532fefdf7c0c26ac9cacd25d35c8f6066185012102a1def88510d7a64499511e20a2c924c3f5d522ac4ec38f07588e716e00279618547dbfe806000000e2540f000b0000006a4730440220597f71c28dd95908168829e08e43f9d6d43420825580dabd044ddcf5a248f47b02201e7ba786856f9acac614d3b57a03e216981b0f3230b0078380411c5909da364101210285ea4a9033d719bcfa0fe2f535dff3f89e15ee0724e9fcfcb498f6d55a6985f46fbf57a305000000dc5d0f00090000006a473044022045078b5694c9ac91dfd4f74800cb9455d5d2a2f60e832e663b3b1e903b15325102201b09a8060ec59562fc0c4cce6c9684a60cfcf0c5148af6b323177225ecc7361d01210363e0523496eef94fc6105f48c0de87493e276a385e3de04415a709db57b1126d",
	}, {
		name: "ok chainbase",
		hex:  "03000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff02000000000000000000000e6a0ce55d0f0033613ca1a89ea2194ef75e000000000000001976a914e84caeb864252bace69af9a129a800c0e96ac8f688ac000000000000000001ce055e000000000000000000ffffffff0800002f646372642f",
	}, {
		name: "ok treasurybase",
		hex:  "03000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff020d3aac0300000000000001c1000000000000000000000e6a0ce55d0f00cdac931bfecd43700000000000000000010d3aac030000000000000000ffffffff00",
	}, {
		name: "ok stakebase",
		hex:  "01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00fffffffffdb06562f75a62a8a45c0431c685a26a8e5a48d09b28cca888d3299d531211090000000001ffffffff0300000000000000000000266a2468479fa7eb9fbd8d8c5939e62ae3e24f576936a3cad5b225fa44e34241f58bb9e45d0f0000000000000000000000086a0645000a000000e4bf09de0500000000001abb76a914afb6b13194f9f0a5f60d21e3eeb412888d9d9d7088ac000000000000000002889a89060000000000000000ffffffff0200005c2580d705000000f83c0f00140000006b483045022100ebab12e6c032b16c73bd413bbd4065cb72c03c3142ba30b59de4fe4bc66b38f402200c6b6f093565552070af47151afee82c47e4af5a4f41c8ea7aeb2e0108c0dba10121026182324373ff5766cce1783e24a96a88bcf4357b55667ac0fbf0f0fa1c31d650",
	}, {
		name: "ok revocation",
		hex:  "0200000001d0da473318d6f1af55a53cbbfd236ce8d0778b2771092ed770928fcf8584aa120000000001ffffffff0121fea7620500000000001abc76a9145902fea3162e16f5fb0886e4302e567500c0250a88ac00000000000000000121fea76205000000afba0e000600000000",
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx, err := w.DecodeTx(test.hex)
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			spew.Dump(tx)
		})
	}
}
