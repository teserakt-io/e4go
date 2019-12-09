package e4go_test

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

import (
	"fmt"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/ed25519"

	e4 "github.com/teserakt-io/e4go"
	"github.com/teserakt-io/e4go/crypto"
)

func ExampleNewSymKeyClient() {
	client, err := e4.NewSymKeyClient([]byte("clientID"), crypto.RandomKey(), "./symClient.json")
	if err != nil {
		panic(err)
	}

	protectedMessage, err := client.ProtectMessage([]byte("very secret message"), "topic/name")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Protected message: %v", protectedMessage)
}

func ExampleNewSymKeyClientPretty() {
	client, err := e4.NewSymKeyClientPretty("clientName", "verySecretPassword", "./symClient.json")
	if err != nil {
		panic(err)
	}

	protectedMessage, err := client.ProtectMessage([]byte("very secret message"), "topic/name")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Protected message: %v", protectedMessage)
}

func ExampleNewPubKeyClient() {
	privateKey, err := crypto.Ed25519PrivateKeyFromPassword("verySecretPassword")
	if err != nil {
		panic(err)
	}

	var c2PubKey [32]byte
	c2EdPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	var c2EdPk [32]byte
	copy(c2EdPk[:], c2EdPubKey)
	extra25519.PublicKeyToCurve25519(&c2PubKey, &c2EdPk)

	client, err := e4.NewPubKeyClient([]byte("clientID"), privateKey, "./pubClient.json", c2PubKey[:])
	if err != nil {
		panic(err)
	}

	protectedMessage, err := client.ProtectMessage([]byte("very secret message"), "topic/name")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Protected message: %v", protectedMessage)
}

func ExampleNewPubKeyClientPretty() {
	var c2PubKey [32]byte
	c2EdPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	var c2EdPk [32]byte
	copy(c2EdPk[:], c2EdPubKey)
	extra25519.PublicKeyToCurve25519(&c2PubKey, &c2EdPk)

	client, pubKey, err := e4.NewPubKeyClientPretty("clientName", "verySecretPassword", "./pubClient.json", c2PubKey[:])
	if err != nil {
		panic(err)
	}
	fmt.Printf("Client public key: %x", pubKey)

	protectedMessage, err := client.ProtectMessage([]byte("very secret message"), "topic/name")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Protected message: %v", protectedMessage)
}
