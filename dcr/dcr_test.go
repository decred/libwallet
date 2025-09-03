package dcr

import (
	"testing"
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
