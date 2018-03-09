package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/trichner/gcrypt/cryptor"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
)

func main() {

	pwFile := flag.String("p", "", "Password file")
	decFlag := flag.Bool("d", false, "Decrypt")
	flag.Parse()

	var err error

	pw, err := readPassword(*pwFile)
	if err != nil {
		exit("%s", err)
	}
	inFile := strings.TrimSpace(flag.Arg(0))

	var in []byte
	if len(inFile) == 0 || inFile == "-" {
		in, err = ioutil.ReadAll(os.Stdin)
	} else {
		in, err = ioutil.ReadFile(inFile)
	}
	if err != nil {
		exit("%s", err)
	}

	inStr := string(in)
	var out string
	if *decFlag {
		out, err = cryptor.DecryptString(pw, inStr)
	} else {
		out, err = cryptor.EncryptString(pw, inStr)
	}

	if err != nil {
		exit("%s", err)
	}

	fmt.Printf("%s", out)
}

func readPassword(pwFile string) ([]byte, error) {

	// read from file
	if len(pwFile) > 0 {
		pw, err := ioutil.ReadFile(pwFile)

		if err != nil {
			return nil, err
		}
		return pw, nil
	}

	// from console
	fmt.Fprint(os.Stderr, "Enter Password: \n")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}

	fmt.Fprint(os.Stderr, "Confirm Password: \n")
	confirmPassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(bytePassword, confirmPassword) {
		return nil, fmt.Errorf("passwords must match")
	}

	return bytePassword, err
}

func exit(format string, msg ...interface{}) {
	fmt.Fprintf(os.Stderr, format, msg...)
	os.Exit(1)
}
