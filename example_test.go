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

package e4_test

import (
	"fmt"

	e4 "github.com/teserakt-io/e4go"
	e4crypto "github.com/teserakt-io/e4go/crypto"
	"golang.org/x/crypto/curve25519"
)

func ExampleNewClient_symIDAndKey() {
	client, err := e4.NewClient(&e4.SymIDAndKey{ID: []byte("clientID"), Key: e4crypto.RandomKey()}, "./symClient.json")
	if err != nil {
		panic(err)
	}

	protectedMessage, err := client.ProtectMessage([]byte("very secret message"), "topic/name")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Protected message: %v", protectedMessage)
}

func ExampleNewClient_symNameAndPassword() {
	client, err := e4.NewClient(&e4.SymNameAndPassword{Name: "clientName", Password: "verySecretPassword"}, "./symClient.json")
	if err != nil {
		panic(err)
	}

	protectedMessage, err := client.ProtectMessage([]byte("very secret message"), "topic/name")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Protected message: %v", protectedMessage)
}

func ExampleNewClient_pubIDAndKey() {
	privateKey, err := e4crypto.Ed25519PrivateKeyFromPassword("verySecretPassword")
	if err != nil {
		panic(err)
	}

	c2PubKey, err := curve25519.X25519(e4crypto.RandomKey(), curve25519.Basepoint)
	if err != nil {
		panic(err)
	}

	client, err := e4.NewClient(&e4.PubIDAndKey{
		ID:       []byte("clientID"),
		Key:      privateKey,
		C2PubKey: c2PubKey,
	}, "./pubClient.json")

	if err != nil {
		panic(err)
	}

	protectedMessage, err := client.ProtectMessage([]byte("very secret message"), "topic/name")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Protected message: %v", protectedMessage)
}

func ExampleNewClient_pubNameAndPassword() {
	c2PubKey, err := curve25519.X25519(e4crypto.RandomKey(), curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	config := &e4.PubNameAndPassword{
		Name:     "clientName",
		Password: "verySecretPassword",
		C2PubKey: c2PubKey,
	}

	client, err := e4.NewClient(config, "./pubClient.json")
	if err != nil {
		panic(err)
	}

	// We may need to get the public key derived from the password:
	pubKey, err := config.PubKey()
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
