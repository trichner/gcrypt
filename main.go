package main

import (
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"syscall"
	"os"
	"bytes"
	"io/ioutil"
	"github.com/trichner/gcrypt/prop"
	"strings"
)

func main() {

	pw := readPassword()

	args := os.Args
	if len(args) < 2 {
		printUsage()
	}

	args = args[1:]
	if args[0] == "enc" {

		encrypt(pw, args)
		return
	}

	if args[0] == "dec" {

		decrypt(pw, args)
		return
	}

	printUsage()
}

func encrypt(password []byte, args []string) {

	if len(args) <= 2 {
		printEncUsage()
		os.Exit(1)
		return
	}

	pkey := args[1]
	fn := args[2]

	plaintext, err := ioutil.ReadFile(fn)
	if err != nil || plaintext == nil {
		exit("cannot read: %s", fn)
	}

	ciphertext, err := prop.Encrypt(password, pkey, string(plaintext))
	if err != nil {
		exit("cannot encrypt: %s", err)
	}

	fmt.Printf("%s\n", ciphertext)
}

func decrypt(password []byte, args []string) {

	if len(args) <= 2 {
		printDecUsage()
		os.Exit(1)
		return
	}

	pkey := args[1]
	fn := args[2]

	cipherbytes, err := ioutil.ReadFile(fn)
	if err != nil || cipherbytes == nil {
		exit("cannot read: %s", fn)
	}

	ciphertext := strings.TrimSpace(string(cipherbytes))
	plaintext, err := prop.Decrypt(password, pkey, string(ciphertext))
	if err != nil {
		exit("cannot encrypt: %s", err)
	}

	fmt.Printf("%s\n", plaintext)
}

func printEncUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s enc <property key> <filename>\n", os.Args[0])
}

func printDecUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s dec <property key> <filename>\n", os.Args[0])
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s ( enc | dec ) <...>\n", os.Args[0])
}

func readPassword() []byte {

	fmt.Fprint(os.Stderr, "Enter Password: \n")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}

	fmt.Fprint(os.Stderr, "Confirm Password: \n")
	confirmPassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(bytePassword, confirmPassword) {
		fmt.Fprint(os.Stderr, "passwords must match\n")
		os.Exit(1)
	}
	return bytePassword
}

func exit(format string, msg ...interface{}) {
	fmt.Fprintf(os.Stderr, format, msg)
	os.Exit(1)
}
