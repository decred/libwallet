package mnemonic

import (
	"bytes"
	"encoding/hex"
	"testing"

	"decred.org/dcrdex/dex/encode"
)

func TestFindWordIndex(t *testing.T) {
	for i := range wordList {
		j, err := wordIndex(wordList[i])
		if err != nil {
			t.Fatal(err)
		}
		if i != int(j) {
			t.Fatalf("wrong index %d returned for %q. expected %d", j, wordList[i], i)
		}
	}

	if _, err := wordIndex("blah"); err == nil {
		t.Fatal("no error for blah")
	}

	if _, err := wordIndex("aaa"); err == nil {
		t.Fatal("no error for aaa")
	}

	if _, err := wordIndex("zzz"); err == nil {
		t.Fatal("no error for zzz")
	}
}

func TestEncodeDecode(t *testing.T) {
	for i := 0; i < 1000; i++ {
		entropyBytes := 16
		if i%2 == 0 {
			entropyBytes = 32
		}
		ogEntropy := encode.RandomBytes(entropyBytes)
		mnemonic, err := GenerateMnemonic(ogEntropy)
		if err != nil {
			t.Fatal(err)
		}
		reEntropy, err := DecodeMnemonic(mnemonic)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reEntropy, ogEntropy) {
			t.Fatal("failed to recover entropy")
		}
	}
}

// TestBip39Vectors taken from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
func TestBip39Vectors(t *testing.T) {
	tests := []struct {
		name, seed, mnemonic string
	}{{
		name:     "ok 12 abandon",
		seed:     "00000000000000000000000000000000",
		mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
	}, {
		name:     "ok 12 legal",
		seed:     "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow",
	}, {
		name:     "ok 12 letter",
		seed:     "80808080808080808080808080808080",
		mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
	}, {
		name:     "ok 12 zoo",
		seed:     "ffffffffffffffffffffffffffffffff",
		mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
	}, {
		name:     "ok 18 abandon",
		seed:     "000000000000000000000000000000000000000000000000",
		mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
	}, {
		name:     "ok 18 legal",
		seed:     "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		mnemonic: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
	}, {
		name:     "ok 18 letter",
		seed:     "808080808080808080808080808080808080808080808080",
		mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
	}, {
		name:     "ok 18 zoo",
		seed:     "ffffffffffffffffffffffffffffffffffffffffffffffff",
		mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
	}, {
		name:     "ok 24 abandon",
		seed:     "0000000000000000000000000000000000000000000000000000000000000000",
		mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
	}, {
		name:     "ok 24 legal",
		seed:     "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		mnemonic: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
	}, {
		name:     "ok 24 letter",
		seed:     "8080808080808080808080808080808080808080808080808080808080808080",
		mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
	}, {
		name:     "ok 24 zoo",
		seed:     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
	}, {
		name:     "ok 12 ozone",
		seed:     "9e885d952ad362caeb4efe34a8e91bd2",
		mnemonic: "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
	}, {
		name:     "ok 18 gravity",
		seed:     "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
		mnemonic: "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
	}, {
		name:     "ok 24 hamster",
		seed:     "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
		mnemonic: "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
	}, {
		name:     "ok 12 scheme",
		seed:     "c0ba5a8e914111210f2bd131f3d5e08d",
		mnemonic: "scheme spot photo card baby mountain device kick cradle pact join borrow",
	}, {
		name:     "ok 18 horn",
		seed:     "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
		mnemonic: "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
	}, {
		name:     "ok 24 panda",
		seed:     "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
		mnemonic: "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
	}, {
		name:     "ok 12 cat",
		seed:     "23db8160a31d3e0dca3688ed941adbf3",
		mnemonic: "cat swing flag economy stadium alone churn speed unique patch report train",
	}, {
		name:     "ok 18 light",
		seed:     "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
		mnemonic: "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
	}, {
		name:     "ok 24 all",
		seed:     "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
		mnemonic: "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
	}, {
		name:     "ok 12 vessel",
		seed:     "f30f8c1da665478f49b001d94c5fc452",
		mnemonic: "vessel ladder alter error federal sibling chat ability sun glass valve picture",
	}, {
		name:     "ok 18 scissors",
		seed:     "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
		mnemonic: "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
	}, {
		name:     "ok 24 void",
		seed:     "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
		mnemonic: "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testSeed, err := hex.DecodeString(test.seed)
			if err != nil {
				t.Fatal(err)
			}
			mnemonic, err := GenerateMnemonic(testSeed)
			if err != nil {
				t.Fatal(err)
			}
			if mnemonic != test.mnemonic {
				t.Fatalf("expected mnemonic %q but got %q", test.mnemonic, mnemonic)
			}
			seed, err := DecodeMnemonic(test.mnemonic)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(seed, testSeed) {
				t.Fatalf("expected seed %x but got %x", testSeed, seed)
			}
		})
	}
}
