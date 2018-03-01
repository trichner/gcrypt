package cryptor

import "encoding/hex"

func EncryptString(password []byte, plaintext string) (string, error) {

	cipherbytes, err := Encrypt(password, []byte(plaintext))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(cipherbytes), nil
}

func DecryptString(password []byte, ciphertext string) (string, error) {

	cipherbytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	plainbytes, err := Decrypt(password, cipherbytes)
	if err != nil {
		return "", err
	}

	return string(plainbytes), nil
}
