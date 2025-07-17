package dcr

import (
	"encoding/hex"
	"errors"

	"github.com/kevinburke/nacl"
	"github.com/kevinburke/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

var (
	ErrInvalidPassphrase = errors.New("invalid_passphrase")
)

// makeEncryptionKey loads a nacl.Key using a cryptographic key generated from
// the provided passphrase via scrypt.Key.
func makeEncryptionKey(pass []byte) (nacl.Key, error) {
	const N, r, p, keyLength = 1 << 15, 8, 1, 32
	keyBytes, err := scrypt.Key(pass, nil, N, r, p, keyLength)
	if err != nil {
		return nil, err
	}
	return nacl.Load(hex.EncodeToString(keyBytes))
}

// EncryptData encrypts the provided data with the provided passphrase.
func EncryptData(data, passphrase []byte) ([]byte, error) {
	key, err := makeEncryptionKey(passphrase)
	if err != nil {
		return nil, err
	}
	return secretbox.EasySeal(data, key), nil
}

// DecryptData uses the provided passphrase to decrypt the provided data.
func DecryptData(data, passphrase []byte) ([]byte, error) {
	key, err := makeEncryptionKey(passphrase)
	if err != nil {
		return nil, err
	}

	decryptedData, err := secretbox.EasyOpen(data, key)
	if err != nil {
		return nil, ErrInvalidPassphrase
	}

	return decryptedData, nil
}
