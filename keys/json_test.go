package keys

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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestFromRawJSON(t *testing.T) {
	t.Run("FromRawJSON properly decode json ed25519 keys", func(t *testing.T) {
		privateKey := []byte("privateKey")
		signerID := []byte("signerID")
		c2PubKey := []byte{}
		c2PubKeyStr, err := json.Marshal(c2PubKey)
		if err != nil {
			t.Fatalf("Failed to encode c2PubKey to string: %v", err)
		}

		pubKeyID := "pubKeyID1"
		pubKeyKey := []byte("pubKeyKey1")

		jsonKey := []byte(fmt.Sprintf(`{
				"keyType": %d,
				"keyData":{
					"PrivateKey":"%s",
					"SignerID":"%s",
					"C2PubKey":%s,
					"PubKeys":{
						"%s": "%s"
					}
				}
			}`,
			pubKeyMaterialType,
			base64.StdEncoding.EncodeToString(privateKey),
			base64.StdEncoding.EncodeToString(signerID),
			c2PubKeyStr,
			pubKeyID,
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

		pk, ok := typedKey.PubKeys[pubKeyID]
		if !ok {
			t.Fatalf("Expected pubkeys to hold a key for id %s", pubKeyID)
		}

		if !bytes.Equal(pk, pubKeyKey) {
			t.Fatalf("Invalid pubKey: got %v, wanted %v", pk, pubKeyKey)
		}
	})

	t.Run("FromRawJSON properly decode json symmetric keys", func(t *testing.T) {
		privateKey := []byte("privateKey")

		jsonKey := []byte(fmt.Sprintf(`{
				"keyType": %d,
				"keyData":{
					"Key":"%s"
				}
			}`,
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
}
