// Copyright 2019 Teserakt AG
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
	"log"
	"os"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"

	e4crypto "github.com/teserakt-io/e4go/crypto"
)

// List of supported KeyTypes
const (
	KeyTypeSymmetric  = "symmetric"
	KeyTypeEd25519    = "ed25519"
	KeyTypeCurve25519 = "curve25519"
)

func main() {
	var keyType string
	var out string
	var force bool

	log.SetFlags(0)

	keyTypeHelp := fmt.Sprintf("type of the key to generate (one of %q, %q, %q)", KeyTypeSymmetric, KeyTypeEd25519, KeyTypeCurve25519)

	flag.StringVar(&keyType, "type", "symmetric", keyTypeHelp)
	flag.StringVar(&out, "out", "", "file path where the key will be generated (required)")
	flag.BoolVar(&force, "force", false, "force overwritting key file if it exists")
	flag.Parse()

	if len(out) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	var privKey []byte
	var pubKey []byte
	var err error

	switch keyType {
	case KeyTypeSymmetric:
		privKey = e4crypto.RandomKey()
	case KeyTypeEd25519:
		pubKey, privKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatalf("failed to generate ed25519 key: %v\n", err)
		}
	case KeyTypeCurve25519:
		privKey = e4crypto.RandomKey()
		pubKey, err = curve25519.X25519(privKey, curve25519.Basepoint)
		if err != nil {
			log.Fatalf("failed to generate curve25519 key: %v\n", err)
		}
	default:
		log.Fatalf("unknown key type: %s\n", keyType)
	}

	if err := writeKey(privKey, pubKey, out, force); err != nil {
		log.Fatal(err)
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
