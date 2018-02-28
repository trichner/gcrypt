package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	VERSION_BYTE         = 0x01
	VERSION_BYTE_LENGTH  = 1
	AES_KEY_BITS_LENGTH  = 128
	GCM_IV_BYTES_LENGTH  = 12
	GCM_TAG_BYTES_LENGTH = 16
	PBKDF2_ITERATIONS    = 16384
	PBKDF2_SALT_STR      = "4d3fe0d71d2abd2828e7a3196ea450d4"
)

var PBKDF2_SALT, _ = hex.DecodeString(s)

func deriveKey(password []byte, keyBytesSize int) []byte {
	key := pbkdf2.Key(password, PBKDF2_SALT, PBKDF2_ITERATIONS, keyBytesSize, sha256.New)
}

func Encrypt(password, plaintext []byte) ([]byte, error) {

	// derive the AES key
	key := deriveKey(password, AES_KEY_BITS_LENGTH/8)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, error
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	headerLen := VERSION_BYTE_LENGTH + GCM_IV_BYTES_LENGTH
	ciphertext := make([]byte, headerLen+GCM_TAG_BYTES_LENGTH+len(plaintext))
	ciphertext[0] = VERSION_BYTE

	nonce := ciphertext[VERSION_BYTE_LENGTH:headerLen]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext = ciphertext[:headerLen]
	fmt.Printf("nonce: %x\n", ciphertext)

	aesgcm.Seal(ciphertext, nonce, plaintext, ciphertext[:headerLen])

	fmt.Printf("%x\n", ciphertext)
	return ciphertext, nil
}

func ExampleNewGCMDecrypter() {
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.
	key := []byte("AES256Key-32Characters1234567890")
	ciphertext, _ := hex.DecodeString("2df87baf86b5073ef1f03e3cc738de75b511400f5465bb0ddeacf47ae4dc267d")

	nonce, _ := hex.DecodeString("afb8a7579bf971db9f8ceeed")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%s\n", plaintext)
	// Output: exampleplaintext
}

func main() {
	ExampleNewGCMEncrypter()
	ExampleNewGCMDecrypter()
}
