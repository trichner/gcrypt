package cryptor_test

import (
	"testing"
	"fmt"
	"github.com/trichner/gcrypt/cryptor"
	"github.com/stretchr/testify/assert"
)

func TestCryptSuccess(t *testing.T) {

	password := []byte("hunter12")
	plaintext := []byte("Hello World!")

	fmt.Printf("Plaintext: %d bytes, '%s'\n", len(plaintext), plaintext)

	ciphertext, err := cryptor.Encrypt(password, plaintext)
	assert.NoError(t, err)

	fmt.Printf("Ciphertext: %d bytes, %0x\n", len(ciphertext), ciphertext)

	decrypted, err := cryptor.Decrypt(password, ciphertext)
	assert.NoError(t, err)

	fmt.Printf("Plaintext: %d bytes, '%s'\n", len(decrypted), decrypted)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncrypt(t *testing.T) {

	password := []byte("hunter12")
	plaintext := []byte("Hello World!")

	lastIv := make([]byte, 12)
	lastEncrypted := make([]byte, 0)
	for i := 0; i < 100; i++ {
		ciphertext, err := cryptor.Encrypt(password, plaintext)
		assert.NoError(t, err)

		// check for static version byte
		assert.NotNil(t, ciphertext)
		assert.Equal(t, byte(0x01), ciphertext[0])

		// iv must not be equal
		iv := ciphertext[1:12]
		assert.NotEqual(t, lastIv, iv)
		lastIv = iv

		// encrypted bytes must not be equal
		encrypted := ciphertext[12:]
		assert.NotEqual(t, lastEncrypted, encrypted)
		lastEncrypted = encrypted
	}
}

func TestDecryptTampered(t *testing.T) {

	password := []byte("hunter12")
	plaintext := []byte("Hello World!")

	ciphertext, err := cryptor.Encrypt(password, plaintext)
	assert.NoError(t, err)

	for i := 0; i < len(ciphertext); i++ {
		for j := uint(0); j < 8; j++ {
			tampered := make([]byte, len(ciphertext))
			copy(tampered, ciphertext)
			tampered[i] = tampered[i] ^ (1 << j)

			_, err := cryptor.Decrypt(password, tampered)
			assert.Error(t, err, "Tampered byte %d, bit %d ciphertext must result in decryption error.", i, j)
		}
	}
}

func TestDecryptTamperedPassword(t *testing.T) {

	password := []byte("hunter12")
	plaintext := []byte("Hello World!")

	ciphertext, err := cryptor.Encrypt(password, plaintext)
	assert.NoError(t, err)

	for i := 0; i < len(password); i++ {
		for j := uint(0); j < 8; j++ {
			tamperedPassword := make([]byte, len(password))
			copy(tamperedPassword, password)
			tamperedPassword[i] = tamperedPassword[i] ^ (1 << j)

			_, err := cryptor.Decrypt(tamperedPassword, ciphertext)
			assert.Error(t, err, "Tampered byte %d, bit %d password must result in decryption error.", i, j)
		}
	}
}
