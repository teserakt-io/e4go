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

package e4_test

import (
	"fmt"

	e4 "github.com/teserakt-io/e4go"
	e4crypto "github.com/teserakt-io/e4go/crypto"
)

func ExampleNewSymKeyClient_idAndKey() {
	client, err := e4.NewSymKeyClient(e4.SymKeyIDAndKey([]byte("clientID"), e4crypto.RandomKey()), "./symClient.json")
	if err != nil {
		panic(err)
	}

	protectedMessage, err := client.ProtectMessage([]byte("very secret message"), "topic/name")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Protected message: %v", protectedMessage)
}

func ExampleNewSymKeyClient_nameAndPassword() {
	client, err := e4.NewSymKeyClient(e4.SymKeyNameAndPassword("clientName", "verySecretPassword"), "./symClient.json")
	if err != nil {
		panic(err)
	}

	protectedMessage, err := client.ProtectMessage([]byte("very secret message"), "topic/name")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Protected message: %v", protectedMessage)
}

func ExampleNewPubKeyClient_idAndKey() {
	privateKey, err := e4crypto.Ed25519PrivateKeyFromPassword("verySecretPassword")
	if err != nil {
		panic(err)
	}

	c2PubKey, _, err := e4crypto.RandomCurve25519Keys()
	if err != nil {
		panic(err)
	}

	client, _, err := e4.NewPubKeyClient(e4.PubKeyIDAndKey([]byte("clientID"), privateKey), "./pubClient.json", c2PubKey)
	if err != nil {
		panic(err)
	}

	protectedMessage, err := client.ProtectMessage([]byte("very secret message"), "topic/name")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Protected message: %v", protectedMessage)
}

func ExampleNewPubKeyClient_nameAndPassword() {
	c2PubKey, _, err := e4crypto.RandomCurve25519Keys()
	if err != nil {
		panic(err)
	}

	client, pubKey, err := e4.NewPubKeyClient(e4.PubKeyNameAndPassword("clientName", "verySecretPassword"), "./pubClient.json", c2PubKey)
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
