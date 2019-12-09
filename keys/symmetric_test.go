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

package keys

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"

	e4crypto "github.com/teserakt-io/e4go/crypto"
)

func TestNewSymKeyFromPassword(t *testing.T) {
	password := "test password random"
	expectedKey, err := e4crypto.DeriveSymKey(password)
	if err != nil {
		t.Fatalf("Failed to derive symKeyMaterialMaterial: %v", err)
	}

	k, err := NewSymKeyMaterialFromPassword(password)
	if err != nil {
		t.Fatalf("Failed to create symKeyMaterial: %v", err)

	}

	tk, ok := k.(*symKeyMaterial)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted symKeyMaterial", k)
	}

	if !bytes.Equal(tk.Key, expectedKey) {
		t.Fatalf("Invalid key: got %v, wanted %v", tk.Key, expectedKey)
	}
}

func TestNewSymKey(t *testing.T) {
	t.Run("symKeyMaterial creates key properly", func(t *testing.T) {
		expectedKey, err := e4crypto.DeriveSymKey("test password random")
		if err != nil {
			t.Fatalf("Failed to derive symKeyMaterialMaterial: %v", err)
		}

		k, err := NewSymKeyMaterial(expectedKey)
		if err != nil {
			t.Fatalf("Failed to create symKeyMaterial: %v", err)
		}

		tk, ok := k.(*symKeyMaterial)
		if !ok {
			t.Fatalf("Unexpected type: got %T, wanted symKeyMaterial", k)
		}

		if !bytes.Equal(tk.Key, expectedKey) {
			t.Fatalf("Invalid key: got %v, wanted %v", tk.Key, expectedKey)
		}
	})

	t.Run("creating symKeyMaterial with bad keys returns errors", func(t *testing.T) {
		zeroKey := make([]byte, e4crypto.KeyLen)
		tooShortKey := make([]byte, e4crypto.KeyLen-1)
		tooLongKey := make([]byte, e4crypto.KeyLen+1)

		rand.Read(tooShortKey)
		rand.Read(tooLongKey)

		badKeys := [][]byte{
			[]byte{},
			zeroKey,
			tooShortKey,
			tooLongKey,
		}

		for _, badKey := range badKeys {
			if _, err := NewSymKeyMaterial(badKey); err == nil {
				t.Fatalf("Expected an error when trying to create a symKeyMaterial with key %v", badKey)
			}
		}
	})
}

func TestNewRandomSymKey(t *testing.T) {
	k, err := NewRandomSymKeyMaterial()
	if err != nil {
		t.Fatalf("Failed to create new random symKeyMaterial: %v", err)
	}

	tk, ok := k.(*symKeyMaterial)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted symKeyMaterial", k)
	}

	if len(tk.Key) == 0 {
		t.Fatal("Expected key to have been set")
	}
}

func TestSymKeyProtectUnprotectMessage(t *testing.T) {
	key := e4crypto.RandomKey()

	symKeyMaterial, err := NewSymKeyMaterial(key)
	if err != nil {
		t.Fatalf("Failed to create symKeyMaterial: %v", err)
	}

	topicKey := e4crypto.RandomKey()
	expectedMessage := []byte("some test message")

	protected, err := symKeyMaterial.ProtectMessage(expectedMessage, topicKey)
	if err != nil {
		t.Fatalf("Failed to protect message: %v", err)
	}

	unprotected, err := symKeyMaterial.UnprotectMessage(protected, topicKey)
	if err != nil {
		t.Fatalf("Failed to unprotect message: %v", err)
	}

	if !bytes.Equal(unprotected, expectedMessage) {
		t.Fatalf("Invalid unprotected message: got %v, wanted %v", unprotected, expectedMessage)
	}

	if _, err := symKeyMaterial.ProtectMessage([]byte("message"), []byte("not a key")); err == nil {
		t.Fatalf("Expected protectMessage to fail when given an invalid topic key")
	}
}

func TestSymKeyUnprotectCommand(t *testing.T) {
	command := []byte{0x01, 0x02, 0x03, 0x04}
	key := e4crypto.RandomKey()

	symKeyMaterial, err := NewSymKeyMaterial(key)
	if err != nil {
		t.Fatalf("Failed to create symKeyMaterial: %v", err)
	}

	protectedCommand, err := e4crypto.ProtectSymKey(command, key)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	unprotectedCommand, err := symKeyMaterial.UnprotectCommand(protectedCommand)
	if err != nil {
		t.Fatalf("Failed to unprotected command: %v", err)
	}

	if !bytes.Equal(unprotectedCommand, command) {
		t.Fatalf("Invalid unprotected command: got %v, wanted %v", unprotectedCommand, command)
	}
}

func TestSymKeySetKey(t *testing.T) {
	key := e4crypto.RandomKey()

	k, err := NewRandomSymKeyMaterial()
	if err != nil {
		t.Fatalf("Failed to create symKeyMaterial: %v", err)
	}

	tk, ok := k.(*symKeyMaterial)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted symKeyMaterial", k)
	}

	if bytes.Equal(tk.Key, key) {
		t.Fatalf("Invalid key: got %v, wanted %v", tk.Key, key)
	}

	if err := tk.SetKey(key); err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	if !bytes.Equal(tk.Key, key) {
		t.Fatalf("Invalid key: got %v, wanted %v", tk.Key, key)
	}

	key[0] = key[0] + 1
	if bytes.Equal(tk.Key, key) {
		t.Fatal("Expected private key slice to have been copied, but it is still pointing to same slice")
	}

	if err := tk.SetKey([]byte("not a key")); err == nil {
		t.Fatal("Expected setKey to fail with an invalid key")
	}
}

func TestSymKeyMarshalJSON(t *testing.T) {
	expectedKey := e4crypto.RandomKey()
	k, err := NewSymKeyMaterial(expectedKey)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	jsonKey, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("Failed to marshal key to json: %v", err)
	}

	unmarshalledKey, err := FromRawJSON(jsonKey)
	if err != nil {
		t.Fatalf("Failed to unmarshal key from json: %v", err)
	}

	if !reflect.DeepEqual(unmarshalledKey, k) {
		t.Fatalf("Invalid unmarshalled key: got %v, wanted %#v", unmarshalledKey, k)
	}
}
