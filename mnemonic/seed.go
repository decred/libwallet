package mnemonic

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// DecodeMnemonic decodes the entropy and checksum from mnemonic and validates
// the checksum.
func DecodeMnemonic(mnemonic string) ([]byte, error) {
	words := strings.Fields(mnemonic)
	nWords := len(words)
	if nWords < 12 || nWords > 24 {
		return nil, fmt.Errorf("mnemonic wrong size, must be between 12 and 24 got %d", nWords)
	}
	totalBits := nWords * 11
	entropyBytes := (totalBits - 8 + totalBits%8) / 8
	checksumBits := totalBits - entropyBytes*8
	buf := make([]byte, entropyBytes+1)
	var cursor int
	for i := range words {
		v, err := wordIndex(words[i])
		if err != nil {
			return nil, err
		}
		bs := make([]byte, 2)
		binary.BigEndian.PutUint16(bs, v)
		b0, b1 := bs[0], bs[1]
		byteIdx := cursor / 8
		avail := 8 - (cursor % 8)
		// Take the last three bits from the first byte, b0.
		if avail < 3 {
			buf[byteIdx] |= b0 >> (3 - avail)
			cursor += avail
			byteIdx++
			n := 3 - avail
			buf[byteIdx] = b0 << (8 - n)
			cursor += n
		} else {
			buf[byteIdx] |= (b0 << (avail - 3))
			cursor += 3
		}
		// Append the entire second byte.
		byteIdx = cursor / 8
		avail = 8 - (cursor % 8)
		buf[byteIdx] |= b1 >> (8 - avail)
		cursor += avail
		if avail < 8 {
			byteIdx++
			n := 8 - avail
			buf[byteIdx] |= b1 << (8 - n)
			cursor += n
		}
	}
	// The first bits of the last byte are the checksum.
	acquiredChecksum := buf[entropyBytes] >> (8 - checksumBits)
	h := sha256.Sum256(buf[:entropyBytes])
	expectedChecksum := h[0] >> (8 - checksumBits)
	if acquiredChecksum != expectedChecksum {
		return nil, errors.New("checksum mismatch")
	}
	entropy := buf[:entropyBytes]
	return entropy, nil
}

// GenerateMnemonic generates a mnemonic seed from entropy.
func GenerateMnemonic(entropy []byte) (string, error) {
	entropyBytes := len(entropy)
	entropyBits := entropyBytes * 8
	if entropyBits < 128 || entropyBits > 256 {
		return "", fmt.Errorf("entropy wrong length, must be between 128 and 256 bits got %d", entropyBits)
	}
	seedWords := entropyBits/11 + 1
	checksumBits := seedWords*11 - entropyBits
	checksumMask := 256 - 1<<(8-checksumBits)
	buf := make([]byte, entropyBytes+1) // extra byte for checksum bits
	copy(buf[:entropyBytes], entropy)
	// checksum
	h := sha256.Sum256(buf[:entropyBytes])
	buf[entropyBytes] = h[0] & uint8(checksumMask)
	var cursor int
	words := make([]string, seedWords)
	for i := 0; i < seedWords; i++ {
		idxB := make([]byte, 2)
		byteIdx := cursor / 8
		remain := 8 - (cursor % 8)
		// We only write three bits to the first byte of the uint16.
		if remain < 3 {
			clearN := 8 - remain
			masked := (buf[byteIdx] << clearN) >> clearN
			idxB[0] = masked << (3 - remain)
			cursor += remain
			byteIdx++
			n := 3 - remain
			idxB[0] |= buf[byteIdx] >> (8 - n)
			cursor += n
		} else {
			// Bits we want are from index (8 - remain) to (11 - remain).
			idxB[0] = (buf[byteIdx] << (8 - remain)) >> 5
			cursor += 3
		}
		// Write all 8 bits of the second byte of the uint16.
		byteIdx = cursor / 8
		remain = 8 - (cursor % 8)
		idxB[1] = buf[byteIdx] << (8 - remain)
		cursor += remain
		if remain < 8 {
			n := 8 - remain
			byteIdx++
			idxB[1] |= buf[byteIdx] >> (8 - n)
			cursor += n
		}
		idx := binary.BigEndian.Uint16(idxB)
		words[i] = wordList[idx]
	}
	return strings.Join(words, " "), nil
}

func wordIndex(word string) (uint16, error) {
	i := sort.Search(len(wordList), func(i int) bool {
		return strings.Compare(wordList[i], word) >= 0
	})
	if i == len(wordList) {
		return 0, fmt.Errorf("word %q exceeded range", word)
	}
	if wordList[i] != word {
		return 0, fmt.Errorf("word %q not known. closest match lexicographically is %q", word, wordList[i])
	}
	return uint16(i), nil
}
