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

package keys

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"

	e4crypto "github.com/teserakt-io/e4go/crypto"
)

var pubKeyJSONTempate = `{
	"keyType": %d,
	"keyData":{
		"PrivateKey":"%s",
		"SignerID":"%s",
		"C2PubKey":%s,
		"PubKeys":{
			"%s": "%s"
		}
	}
}`

var symKeyJSONTemplate = `{
	"keyType": %d,
	"keyData":{
		"Key":"%s"
	}
}`

func TestFromRawJSON(t *testing.T) {
	t.Run("FromRawJSON properly decode json ed25519 keys", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("Failed to generate private key: %v", err)
		}

		signerID := e4crypto.HashIDAlias("signerID")
		c2PubKey, err := curve25519.X25519(e4crypto.RandomKey(), curve25519.Basepoint)
		if err != nil {
			t.Fatalf("Failed to generate c2 public key")
		}

		c2PubKeyStr, err := json.Marshal(c2PubKey)
		if err != nil {
			t.Fatalf("Failed to encode c2PubKey to string: %v", err)
		}

		pubKeyID := e4crypto.HashIDAlias("pubKeyID1")
		pubKeyKey, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("Failed to generate public key: %v", err)
		}

		jsonKey := []byte(fmt.Sprintf(pubKeyJSONTempate,
			pubKeyMaterialType,
			base64.StdEncoding.EncodeToString(privateKey),
			base64.StdEncoding.EncodeToString(signerID),
			c2PubKeyStr,
			hex.EncodeToString(pubKeyID),
			base64.StdEncoding.EncodeToString(pubKeyKey),
		))

		k, err := FromRawJSON(jsonKey)
		if err != nil {
			t.Fatalf("Got error %v, wanted no error when unmarshalling json key", err)
		}

		typedKey, ok := k.(*pubKeyMaterial)
		if !ok {
			t.Fatalf("Wrong key type: got %T, wanted pubKeyMaterial", k)
		}

		if !bytes.Equal(typedKey.PrivateKey, privateKey) {
			t.Fatalf("Invalid private key: got %v, wanted %v", typedKey.PrivateKey, privateKey)
		}

		if !bytes.Equal(typedKey.SignerID, signerID) {
			t.Fatalf("Invalid signer ID: got %v, wanted %v", typedKey.SignerID, signerID)
		}

		if !bytes.Equal(typedKey.C2PubKey, c2PubKey) {
			t.Fatalf("Invalid C2PubKey: got %v, wanted %v", typedKey.C2PubKey, c2PubKey)
		}

		if len(typedKey.PubKeys) != 1 {
			t.Fatalf("Invalid pubKey count: got %d, wanted 1", len(typedKey.PubKeys))
		}

		pk, ok := typedKey.PubKeys[hex.EncodeToString(pubKeyID)]
		if !ok {
			t.Fatalf("Expected pubkeys to hold a key for id %s", pubKeyID)
		}

		if !bytes.Equal(pk, pubKeyKey) {
			t.Fatalf("Invalid pubKey: got %v, wanted %v", pk, pubKeyKey)
		}
	})

	t.Run("FromRawJSON properly decode json symmetric keys", func(t *testing.T) {
		privateKey := e4crypto.RandomKey()

		jsonKey := []byte(fmt.Sprintf(symKeyJSONTemplate,
			symKeyMaterialType,
			base64.StdEncoding.EncodeToString(privateKey),
		))

		k, err := FromRawJSON(jsonKey)
		if err != nil {
			t.Fatalf("Got error %v when unmarshalling json key, wanted no error", err)
		}

		typedKey, ok := k.(*symKeyMaterial)
		if !ok {
			t.Fatalf("Invalid key type: got %T, wanted symKeyMaterial", k)
		}

		if !bytes.Equal(typedKey.Key, privateKey) {
			t.Fatalf("Invalid private key: got %v, wanted %v", typedKey.Key, privateKey)
		}
	})

	t.Run("FromRawJSON properly errors on invalid json input", func(t *testing.T) {
		invalidJSONKeys := []string{
			`{}`,
			fmt.Sprintf(`{"keyType": %d}`, symKeyMaterialType),
			`{"keyData": {}}`,
			fmt.Sprintf(`{"keyType": %d, "keyData": {}}`, -1),
			`{"keyType": "nope", "keyData": {}}`,
			fmt.Sprintf(`{"keyType": %d, "keyData": ""}`, symKeyMaterialType),
			"[]",
		}

		for _, invalidJSON := range invalidJSONKeys {
			_, err := FromRawJSON([]byte(invalidJSON))
			if err == nil {
				t.Fatalf("Expected an error when unmarshalling json `%s`", invalidJSON)
			}
		}
	})

	t.Run("FromRawJSON properly returns error when loading invalid pubkey data", func(t *testing.T) {
		validPrivateKey := e4crypto.RandomKey()
		validID := e4crypto.HashIDAlias("random")
		validCurvePubKey, err := curve25519.X25519(e4crypto.RandomKey(), curve25519.Basepoint)
		if err != nil {
			t.Fatalf("Failed to generate c2 pubkey: %v", err)
		}
		validEdPubKey, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("Failed to generate public key: %v", err)
		}

		type testData struct {
			privateKey []byte
			signerID   []byte
			c2PubKey   []byte
			pubKeyID   []byte
			pubKeyKey  []byte
		}

		testDatas := []testData{
			{
				privateKey: validPrivateKey[1:],
				signerID:   validID,
				c2PubKey:   validCurvePubKey,
				pubKeyID:   validID,
				pubKeyKey:  validEdPubKey,
			},
			{
				privateKey: validPrivateKey,
				signerID:   validID[1:],
				c2PubKey:   validCurvePubKey,
				pubKeyID:   validID,
				pubKeyKey:  validEdPubKey,
			},
			{
				privateKey: validPrivateKey,
				signerID:   validID,
				c2PubKey:   validCurvePubKey[1:],
				pubKeyID:   validID,
				pubKeyKey:  validEdPubKey,
			},
			{
				privateKey: validPrivateKey,
				signerID:   validID,
				c2PubKey:   validCurvePubKey,
				pubKeyID:   validID[1:],
				pubKeyKey:  validEdPubKey,
			},
			{
				privateKey: validPrivateKey,
				signerID:   validID,
				c2PubKey:   validCurvePubKey,
				pubKeyID:   validID,
				pubKeyKey:  validEdPubKey[1:],
			},
		}

		for _, testData := range testDatas {

			c2PubKeyStr, err := json.Marshal(testData.c2PubKey)
			if err != nil {
				t.Fatalf("Failed to encode c2PubKey to string: %v", err)
			}

			jsonKey := []byte(fmt.Sprintf(pubKeyJSONTempate,
				pubKeyMaterialType,
				base64.StdEncoding.EncodeToString(testData.privateKey),
				base64.StdEncoding.EncodeToString(testData.signerID),
				c2PubKeyStr,
				hex.EncodeToString(testData.pubKeyID),
				base64.StdEncoding.EncodeToString(testData.pubKeyKey),
			))

			_, err = FromRawJSON(jsonKey)
			if err == nil {
				t.Fatalf("An error was expected while unmarshalling invalid pubkey data %#v", testData)
			}
		}
	})

	t.Run("FromRawJSON properly returns error when loading invalid symkey data", func(t *testing.T) {
		jsonKey := []byte(fmt.Sprintf(symKeyJSONTemplate,
			symKeyMaterialType,
			base64.StdEncoding.EncodeToString(e4crypto.RandomKey()[1:]),
		))

		_, err := FromRawJSON(jsonKey)
		if err == nil {
			t.Fatal("An error was expected while unmarshalling symkey")
		}
	})
}
