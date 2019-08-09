package keys

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"

	e4crypto "gitlab.com/teserakt/e4common/crypto"
)

func TestNewSymKeyFromPassword(t *testing.T) {
	password := "test password"
	expectedKey := e4crypto.DeriveSymKey(password)

	k, err := NewSymKeyFromPassword(password)
	if err != nil {
		t.Fatalf("failed to create symKey: %v", err)
	}

	tk, ok := k.(*symKey)
	if !ok {
		t.Fatal("failed to cast symKey")
	}

	if bytes.Equal(tk.Key, expectedKey) == false {
		t.Fatalf("expected key to be %v, got %v", expectedKey, tk.Key)
	}
}

func TestNewSymKey(t *testing.T) {
	t.Run("symKey creates key properly", func(t *testing.T) {

		expectedKey := e4crypto.DeriveSymKey("test password")

		k, err := NewSymKey(expectedKey)
		if err != nil {
			t.Fatalf("failed to create symKey: %v", err)
		}

		tk, ok := k.(*symKey)
		if !ok {
			t.Fatal("failed to cast symKey")
		}

		if bytes.Equal(tk.Key, expectedKey) == false {
			t.Fatalf("expected key to be %v, got %v", expectedKey, tk.Key)
		}
	})

	t.Run("creating symKey with bad keys returns errors", func(t *testing.T) {
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
			if _, err := NewSymKey(badKey); err == nil {
				t.Fatalf("expected an error when trying to create a symKey with key %v", badKey)
			}
		}
	})
}

func TestNewRandomSymKey(t *testing.T) {
	k, err := NewRandomSymKey()
	if err != nil {
		t.Fatalf("failed to create new random symKey: %v", err)
	}

	tk, ok := k.(*symKey)
	if !ok {
		t.Fatal("failed to cast symKey")
	}

	if len(tk.Key) <= 0 {
		t.Fatal("expected key to have been set")
	}
}

func TestSymKeyProtectUnprotectMessage(t *testing.T) {
	key := e4crypto.RandomKey()

	symKey, err := NewSymKey(key)
	if err != nil {
		t.Fatalf("failed to create symKey: %v", err)
	}

	topicKey := e4crypto.RandomKey()
	expectedMessage := []byte("some test message")

	protected, err := symKey.ProtectMessage(expectedMessage, topicKey)
	if err != nil {
		t.Fatalf("failed to protect message: %v", err)
	}

	unprotected, err := symKey.UnprotectMessage(protected, topicKey)
	if err != nil {
		t.Fatalf("failed to unprotect message: %v", err)
	}

	if bytes.Equal(unprotected, expectedMessage) == false {
		t.Fatalf("expected unprotected message to be %v, got %v", expectedMessage, unprotected)
	}
}

func TestSymKeyUnprotectCommand(t *testing.T) {
	command := []byte{0x01, 0x02, 0x03, 0x04}
	key := e4crypto.RandomKey()

	symKey, err := NewSymKey(key)
	if err != nil {
		t.Fatalf("failed to create symKey: %v", err)
	}

	protectedCommand, err := e4crypto.ProtectSymKey(command, key)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}

	unprotectedCommand, err := symKey.UnprotectCommand(protectedCommand)
	if err != nil {
		t.Fatalf("failed to unprotected command: %v", err)
	}

	if bytes.Equal(unprotectedCommand, command) == false {
		t.Fatalf("expected unprotected command to be %v, got %v", command, unprotectedCommand)
	}
}

func TestSymKeySetKey(t *testing.T) {
	key := e4crypto.RandomKey()

	k, err := NewRandomSymKey()
	if err != nil {
		t.Fatalf("failed to create symKey: %v", err)
	}

	tk, ok := k.(*symKey)
	if !ok {
		t.Fatal("failed to cast symKey")
	}

	if bytes.Equal(tk.Key, key) == true {
		t.Fatal("expected key to be differents")
	}

	if err := tk.SetKey(key); err != nil {
		t.Fatalf("failed to set key: %v", err)
	}

	if bytes.Equal(tk.Key, key) == false {
		t.Fatalf("expected key to be %v, got %v", key, tk.Key)
	}

	key[0] = key[0] + 1
	if bytes.Equal(tk.Key, key) == true {
		t.Fatalf("expected private key to have been copied, seems still pointing to same slice")
	}

	if err := tk.SetKey([]byte("not a key")); err == nil {
		t.Fatal("expected setKey to fail with an invalid key")
	}
}

func TestSymKeyMarshalJSON(t *testing.T) {
	expectedKey := e4crypto.RandomKey()
	k, err := NewSymKey(expectedKey)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jsonKey, err := k.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal key to json: %v", err)
	}

	unmarshalledKey, err := FromRawJSON(jsonKey)
	if err != nil {
		t.Fatalf("failed to unmarshal key from json: %v", err)
	}

	if reflect.DeepEqual(unmarshalledKey, k) == false {
		t.Fatalf("expected unmarshalled key to be %#v, got %#v", k, unmarshalledKey)
	}
}
