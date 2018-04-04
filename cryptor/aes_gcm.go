package cryptor

import (
	"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"crypto/cipher"
	"crypto/aes"
	"crypto/rand"
	"io"
	"fmt"
)

const (
	versionByte      = 0x01
	versionByteLen   = 1
	aesKeyBitsLen    = 128
	gcmIvBytesLen    = 12
	gcmTagBytesLen   = 16
	pbkdf2Iterations = 1024
	pbkdf2SaltStr    = "4d3fe0d71d2abd2828e7a3196ea450d4"
)

var pbkdf2Salt, _ = hex.DecodeString(pbkdf2SaltStr)

func Encrypt(password, plaintext []byte) ([]byte, error) {

	// derive the AES key
	aesgcm, err := newAesGcm(password)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	headerLen := versionByteLen + gcmIvBytesLen
	ciphertext := make([]byte, headerLen+gcmTagBytesLen+len(plaintext))
	ciphertext[0] = versionByte

	nonce := ciphertext[versionByteLen:headerLen]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext = ciphertext[:headerLen]
	ciphertext = aesgcm.Seal(ciphertext, nonce, plaintext, ciphertext[:headerLen])

	return ciphertext, nil
}

func Decrypt(password, ciphertext []byte) ([]byte, error) {

	if ciphertext == nil || len(ciphertext) <= versionByteLen + gcmIvBytesLen + gcmTagBytesLen {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	if ciphertext[0] != versionByte{
		return nil, fmt.Errorf("invalid version: %d", ciphertext[0])
	}

	// derive the AES key
	aesgcm, err := newAesGcm(password)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	headerLen := versionByteLen + gcmIvBytesLen

	nonce := ciphertext[versionByteLen:headerLen]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[headerLen:], ciphertext[:headerLen])
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func deriveKey(password []byte, keyBytesSize int) []byte {
	return pbkdf2.Key(password, pbkdf2Salt, pbkdf2Iterations, keyBytesSize, sha256.New)
}

func newAesGcm(password []byte) (cipher.AEAD, error){

	key := deriveKey(password, aesKeyBitsLen/8)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}
