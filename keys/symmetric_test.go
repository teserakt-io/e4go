package keys

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"

	e4crypto "gitlab.com/teserakt/e4common/crypto"
)

func TestNewSymKeyFromPassword(t *testing.T) {
	password := "test password random"
	expectedKey, err := e4crypto.DeriveSymKey(password)
	if err != nil {
		t.Fatalf("failed to derive symKeyMaterialMaterial: %v", err)
	}

	k, err := NewSymKeyMaterialFromPassword(password)
	if err != nil {
		t.Fatalf("failed to create symKeyMaterial: %v", err)

	}

	tk, ok := k.(*symKeyMaterial)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted symKeyMaterial", k)
	}

	if !bytes.Equal(tk.Key, expectedKey) {
		t.Fatalf("expected key to be %v, got %v", expectedKey, tk.Key)
	}
}

func TestNewSymKey(t *testing.T) {
	t.Run("symKeyMaterial creates key properly", func(t *testing.T) {
		expectedKey, err := e4crypto.DeriveSymKey("test password random")
		if err != nil {
			t.Fatalf("failed to derive symKeyMaterialMaterial: %v", err)
		}

		k, err := NewSymKeyMaterial(expectedKey)
		if err != nil {
			t.Fatalf("failed to create symKeyMaterial: %v", err)
		}

		tk, ok := k.(*symKeyMaterial)
		if !ok {
			t.Fatalf("Unexpected type: got %T, wanted symKeyMaterial", k)
		}

		if !bytes.Equal(tk.Key, expectedKey) {
			t.Fatalf("expected key to be %v, got %v", expectedKey, tk.Key)
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
				t.Fatalf("expected an error when trying to create a symKeyMaterial with key %v", badKey)
			}
		}
	})
}

func TestNewRandomSymKey(t *testing.T) {
	k, err := NewRandomSymKeyMaterial()
	if err != nil {
		t.Fatalf("failed to create new random symKeyMaterial: %v", err)
	}

	tk, ok := k.(*symKeyMaterial)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted symKeyMaterial", k)
	}

	if len(tk.Key) == 0 {
		t.Fatal("expected key to have been set")
	}
}

func TestSymKeyProtectUnprotectMessage(t *testing.T) {
	key := e4crypto.RandomKey()

	symKeyMaterial, err := NewSymKeyMaterial(key)
	if err != nil {
		t.Fatalf("failed to create symKeyMaterial: %v", err)
	}

	topicKey := e4crypto.RandomKey()
	expectedMessage := []byte("some test message")

	protected, err := symKeyMaterial.ProtectMessage(expectedMessage, topicKey)
	if err != nil {
		t.Fatalf("failed to protect message: %v", err)
	}

	unprotected, err := symKeyMaterial.UnprotectMessage(protected, topicKey)
	if err != nil {
		t.Fatalf("failed to unprotect message: %v", err)
	}

	if !bytes.Equal(unprotected, expectedMessage) {
		t.Fatalf("expected unprotected message to be %v, got %v", expectedMessage, unprotected)
	}

	if _, err := symKeyMaterial.ProtectMessage([]byte("message"), []byte("not a key")); err == nil {
		t.Fatalf("expected protectMessage to fail when given an invalid topic key")
	}
}

func TestSymKeyUnprotectCommand(t *testing.T) {
	command := []byte{0x01, 0x02, 0x03, 0x04}
	key := e4crypto.RandomKey()

	symKeyMaterial, err := NewSymKeyMaterial(key)
	if err != nil {
		t.Fatalf("failed to create symKeyMaterial: %v", err)
	}

	protectedCommand, err := e4crypto.ProtectSymKey(command, key)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}

	unprotectedCommand, err := symKeyMaterial.UnprotectCommand(protectedCommand)
	if err != nil {
		t.Fatalf("failed to unprotected command: %v", err)
	}

	if !bytes.Equal(unprotectedCommand, command) {
		t.Fatalf("expected unprotected command to be %v, got %v", command, unprotectedCommand)
	}
}

func TestSymKeySetKey(t *testing.T) {
	key := e4crypto.RandomKey()

	k, err := NewRandomSymKeyMaterial()
	if err != nil {
		t.Fatalf("failed to create symKeyMaterial: %v", err)
	}

	tk, ok := k.(*symKeyMaterial)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted symKeyMaterial", k)
	}

	if bytes.Equal(tk.Key, key) {
		t.Fatal("expected key to be differents")
	}

	if err := tk.SetKey(key); err != nil {
		t.Fatalf("failed to set key: %v", err)
	}

	if !bytes.Equal(tk.Key, key) {
		t.Fatalf("expected key to be %v, got %v", key, tk.Key)
	}

	key[0] = key[0] + 1
	if bytes.Equal(tk.Key, key) {
		t.Fatalf("expected private key to have been copied, seems still pointing to same slice")
	}

	if err := tk.SetKey([]byte("not a key")); err == nil {
		t.Fatal("expected setKey to fail with an invalid key")
	}
}

func TestSymKeyMarshalJSON(t *testing.T) {
	expectedKey := e4crypto.RandomKey()
	k, err := NewSymKeyMaterial(expectedKey)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jsonKey, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("failed to marshal key to json: %v", err)
	}

	unmarshalledKey, err := FromRawJSON(jsonKey)
	if err != nil {
		t.Fatalf("failed to unmarshal key from json: %v", err)
	}

	if !reflect.DeepEqual(unmarshalledKey, k) {
		t.Fatalf("expected unmarshalled key to be %#v, got %#v", k, unmarshalledKey)
	}
}
