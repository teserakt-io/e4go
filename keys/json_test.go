package keys

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
			t.Fatalf("failed to encode c2PubKey to string: %v", err)
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
			t.Fatalf("expected no error when unmarshalling json key, got %v", err)
		}

		tkey, ok := k.(*pubKeyMaterial)
		if !ok {
			t.Fatalf("expected key to be a pubKeyMaterial, got %T", k)
		}

		if !bytes.Equal(tkey.PrivateKey, privateKey) {
			t.Fatalf("expected private key to be %v, got %v", privateKey, tkey.PrivateKey)
		}

		if !bytes.Equal(tkey.SignerID, signerID) {
			t.Fatalf("expected signerID to be %v, got %v", signerID, tkey.SignerID)
		}

		if !bytes.Equal(tkey.C2PubKey, c2PubKey) {
			t.Fatalf("expected C2PubKey to be %v, got %v", c2PubKey, tkey.C2PubKey)
		}

		if len(tkey.PubKeys) != 1 {
			t.Fatalf("expected keys to hold 1 pubkey, got %d", len(tkey.PubKeys))
		}

		pk, ok := tkey.PubKeys[pubKeyID]
		if !ok {
			t.Fatalf("expected pubkeys to hold a key for id %s", pubKeyID)
		}

		if !bytes.Equal(pk, pubKeyKey) {
			t.Fatalf("expected pubKey to be %v, got %v", pubKeyKey, pk)
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
			t.Fatalf("expected no error when unmarshalling json key, got %v", err)
		}

		tkey, ok := k.(*symKeyMaterial)
		if !ok {
			t.Fatalf("expected key to be a symKeyMaterial, got %T", k)
		}

		if !bytes.Equal(tkey.Key, privateKey) {
			t.Fatalf("expected key to be %v, got %v", privateKey, tkey.Key)
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
				t.Fatalf("expected an error when unmarshalling json `%s`", invalidJSON)
			}
		}
	})
}
