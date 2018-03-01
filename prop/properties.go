package prop

import (
	"github.com/trichner/gcrypt/cryptor"
	"strings"
	"fmt"
)

func Encrypt(password []byte, key, value string) (string, error) {

	if len(key) < 1 || strings.Contains(key, ":") {
		return "", fmt.Errorf("inalid property key")
	}

	plaintext := key + ":" + value
	return cryptor.EncryptString(password, plaintext)
}

func Decrypt(password []byte, key, ciphertext string) (string, error) {

	plainstring, err := cryptor.DecryptString(password, ciphertext)
	if err != nil {
		return "", err
	}
	splits := strings.SplitN(plainstring, ":", 2)
	if len(splits) != 2 {
		return "", fmt.Errorf("no tag found in decrypted message")
	}

	if splits[0] != key {
		return "", fmt.Errorf("property key mismatch")
	}

	return splits[1], nil
}
