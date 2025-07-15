// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/nacl/box"
	"io/ioutil"
	"os"
)

var (
	privatePath string
	publicPath  string
)

func init() {
	flag.StringVar(&privatePath, "private", "private.pem", "output path for private key")
	flag.StringVar(&publicPath, "public", "public.pem", "output path for public key")
}

func createBoxFiles(args []string) int {
	flag.Parse()

	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate random key %s\n", err.Error())
		return 1
	}

	privateData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "BOX PRIVATE KEY",
			Bytes: privateKey[:],
		},
	)

	publicData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "BOX PUBLIC KEY",
			Bytes: publicKey[:],
		},
	)

	err = ioutil.WriteFile(privatePath, privateData, 0400)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write to file %s\n", err.Error())
		return 1
	}
	err = ioutil.WriteFile(publicPath, publicData, 0400)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write to file %s\n", err.Error())
		return 1
	}
	return 0
}

func main() {
	os.Exit(createBoxFiles(os.Args))
}
