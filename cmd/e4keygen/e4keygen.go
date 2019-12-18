// Copyright 2018-2019-2020 Teserakt AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ed25519"

	e4crypto "github.com/teserakt-io/e4go/crypto"
)

// List of supported KeyTypes
const (
	KeyTypeSymmetric  string = "symmetric"
	KeyTypeEd25519    string = "ed25519"
	KeyTypeCurve25519 string = "curve25519"
)

func main() {
	var name string
	var keyType string
	var out string
	var force bool

	flag.StringVar(&name, "name", "", "name of the key file to be created (required).")
	flag.StringVar(&keyType, "type", "symmetric", fmt.Sprintf("type of the key to generate (one of \"%s\", \"%s\", \"%s\")", KeyTypeSymmetric, KeyTypeEd25519, KeyTypeCurve25519))
	flag.StringVar(&out, "out", "", "folder path where to write the generated key (default: current folder)")
	flag.BoolVar(&force, "force", false, "force overwritting key file if it exists")
	flag.Parse()

	if len(name) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	keyPath := filepath.Join(out, name)

	var privKey []byte
	var pubKey []byte
	var err error

	switch keyType {
	case KeyTypeSymmetric:
		privKey = e4crypto.RandomKey()
	case KeyTypeEd25519:
		pubKey, privKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			fmt.Printf("failed to generate ed25519 key: %v\n", err)
			os.Exit(1)
		}
	case KeyTypeCurve25519:
		pubKey, privKey, err = e4crypto.RandomCurve25519Keys()
		if err != nil {
			fmt.Printf("failed to generate curve25519 key: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("unknown key type: %s\n", keyType)
		os.Exit(1)
	}

	if err := writeKey(privKey, pubKey, keyPath, force); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func writeKey(privateBytes []byte, publicBytes []byte, filepath string, force bool) error {
	if err := write(privateBytes, filepath, 0600, force); err != nil {
		return fmt.Errorf("failed to write private key %s: %v", filepath, err)
	}

	fmt.Printf("private key successfully written at %s\n", filepath)

	if len(publicBytes) > 0 {
		pubKeyFilepath := fmt.Sprintf("%s.pub", filepath)
		if err := write(publicBytes, pubKeyFilepath, 0644, force); err != nil {
			return fmt.Errorf("failed to write public key %s: %v", pubKeyFilepath, err)
		}
		fmt.Printf("public key successfully written at %s\n", pubKeyFilepath)
	}

	return nil
}

func write(keyBytes []byte, filepath string, perm os.FileMode, force bool) error {
	openFlags := os.O_CREATE | os.O_WRONLY
	if !force {
		openFlags = openFlags | os.O_EXCL
	}

	keyFile, err := os.OpenFile(filepath, openFlags, perm)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	n, err := keyFile.Write(keyBytes)
	if err != nil {
		return err
	}
	if g, w := len(keyBytes), n; g != w {
		return fmt.Errorf("failed to write public key, got %d bytes, wanted %d", g, w)
	}

	return nil
}
