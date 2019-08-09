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
		c2PublicKey := [32]byte{}
		c2PublicKeyStr, err := json.Marshal(c2PublicKey)
		if err != nil {
			t.Fatalf("failed to encode c2PublicKey to string: %v", err)
		}

		pubKeyID := "pubKeyID1"
		pubKeyKey := []byte("pubKeyKey1")

		jsonKey := []byte(fmt.Sprintf(`{
				"keyType": %d,
				"keyData":{
					"PrivateKey":"%s",
					"SignerID":"%s",
					"C2PublicKey":%s,
					"PubKeys":{
						"%s": "%s"
					}
				}
			}`,
			ed25519KeyType,
			base64.StdEncoding.EncodeToString(privateKey),
			base64.StdEncoding.EncodeToString(signerID),
			c2PublicKeyStr,
			pubKeyID,
			base64.StdEncoding.EncodeToString(pubKeyKey),
		))

		k, err := FromRawJSON(jsonKey)
		if err != nil {
			t.Fatalf("expected no error when unmarshalling json key, got %v", err)
		}

		tkey, ok := k.(*ed25519Key)
		if !ok {
			t.Fatalf("expected key to be a ed25519Key, got %T", k)
		}

		if bytes.Equal(tkey.PrivateKey, privateKey) == false {
			t.Fatalf("expected private key to be %v, got %v", privateKey, tkey.PrivateKey)
		}

		if bytes.Equal(tkey.SignerID, signerID) == false {
			t.Fatalf("expected signerID to be %v, got %v", signerID, tkey.SignerID)
		}

		if tkey.C2PublicKey != c2PublicKey {
			t.Fatalf("expected C2PublicKey to be %v, got %v", c2PublicKey, tkey.C2PublicKey)
		}

		if len(tkey.PubKeys) != 1 {
			t.Fatalf("expected keys to hold 1 pubkey, got %d", len(tkey.PubKeys))
		}

		pk, ok := tkey.PubKeys[pubKeyID]
		if !ok {
			t.Fatalf("expected pubkeys to hold a key for id %s", pubKeyID)
		}

		if bytes.Equal(pk, pubKeyKey) == false {
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
			symKeyType,
			base64.StdEncoding.EncodeToString(privateKey),
		))

		k, err := FromRawJSON(jsonKey)
		if err != nil {
			t.Fatalf("expected no error when unmarshalling json key, got %v", err)
		}

		tkey, ok := k.(*symKey)
		if !ok {
			t.Fatalf("expected key to be a symKey, got %T", k)
		}

		if bytes.Equal(tkey.Key, privateKey) == false {
			t.Fatalf("expected key to be %v, got %v", privateKey, tkey.Key)
		}
	})

	t.Run("FromRawJSON properly errors on invalid json input", func(t *testing.T) {
		invalidJSONKeys := []string{
			`{}`,
			fmt.Sprintf(`{"keyType": %d}`, symKeyType),
			`{"keyData": {}}`,
			fmt.Sprintf(`{"keyType": %d, "keyData": {}}`, -1),
			`{"keyType": "nope", "keyData": {}}`,
			fmt.Sprintf(`{"keyType": %d, "keyData": ""}`, symKeyType),
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
