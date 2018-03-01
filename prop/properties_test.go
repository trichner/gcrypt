package prop_test

import (
	"testing"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/trichner/gcrypt/prop"
)

func TestCryptPropertySuccess(t *testing.T) {

	password := []byte("hunter12")
	key := "test"
	value := "Hello Wörld!"

	fmt.Printf("Plaintext: '%s':'%s'\n", key, value)
	ciphertext, err := prop.Encrypt(password, key, value)
	assert.NoError(t, err)

	fmt.Printf("Ciphertext: %d bytes, %s\n", len(ciphertext), ciphertext)

	decrypted, err := prop.Decrypt(password, key, ciphertext)
	assert.NoError(t, err)

	fmt.Printf("Plaintext: '%s'\n", decrypted)
	assert.Equal(t, value, decrypted)
}

func TestCryptPropertyBadKey(t *testing.T) {

	password := []byte("hunter12")
	value := "Hello Wörld!"

	var err error
	var key string

	key = "te:st"
	_, err = prop.Encrypt(password, key, value)
	assert.Error(t, err)

	key = ""
	_, err = prop.Encrypt(password, key, value)
	assert.Error(t, err)
}

func TestCryptPropertyWrongKey(t *testing.T) {

	password := []byte("hunter12")
	key := "test"
	key2 := "Test?"
	value := "Hello Wörld!"

	var err error

	ciphertext, err := prop.Encrypt(password, key, value)
	assert.NoError(t, err)

	_, err = prop.Decrypt(password, key2, ciphertext)
	assert.Error(t, err)
}
