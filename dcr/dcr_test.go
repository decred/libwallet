package dcr

import (
	"testing"

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
