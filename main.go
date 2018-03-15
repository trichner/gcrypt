package main

import (
	"bufio"
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
	lstFile := flag.String("l", "", "Encrypt list, new-line separated list")
	flag.Parse()

	var err error

	pw, err := readPassword(*pwFile)
	if err != nil {
		exit("%s", err)
	}

	// do we have a list input?
	if len(*lstFile) != 0 {
		lines, err := readList(*lstFile)
		if err != nil {
			exit("%s", err)
		}

		for _, p := range lines {
			out, err := cryptor.EncryptString(pw, p.line)
			if err != nil {
				exit("%s", err)
			}
			fmt.Printf("%s,%s\n", p.key, out)
		}
		return
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

type property struct {
	key, line string
}

func readList(listFile string) ([]property, error) {
	f, err := os.Open(listFile)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(f)
	if err != nil {
		return nil, err
	}

	properties := make([]property, 0, 10)
	for scanner.Scan() {
		l := scanner.Text()
		if len(l) == 0 {
			continue
		}

		splits := strings.SplitN(l, ":", 2)
		if len(splits) != 2 {
			return nil, fmt.Errorf("no tag found in property: " + l)
		}

		p := property{
			key:  splits[0],
			line: l,
		}
		properties = append(properties, p)
	}
	err = scanner.Err()
	return properties, err
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
