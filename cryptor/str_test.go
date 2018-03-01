package cryptor_test

import (
	"testing"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/trichner/gcrypt/cryptor"
)

func TestStringCryptSuccess(t *testing.T) {

	password := []byte("hunter12")
	plaintext := "Hello Wörld!"

	fmt.Printf("Plaintext: %d bytes, '%s'\n", len(plaintext), plaintext)

	ciphertext, err := cryptor.EncryptString(password, plaintext)
	assert.NoError(t, err)

	fmt.Printf("Ciphertext: %d bytes, %s\n", len(ciphertext), ciphertext)

	decrypted, err := cryptor.DecryptString(password, ciphertext)
	assert.NoError(t, err)

	fmt.Printf("Plaintext: %d bytes, '%s'\n", len(decrypted), decrypted)
	assert.Equal(t, plaintext, decrypted)
}
