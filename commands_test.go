package e4go

import (
	"bytes"
	"crypto/rand"
	"testing"

	e4crypto "github.com/teserakt-io/e4go/crypto"
	"golang.org/x/crypto/ed25519"
)

var invalidKeys = [][]byte{
	nil,
	[]byte{},
	make([]byte, e4crypto.KeyLen-1),
	make([]byte, e4crypto.KeyLen+1),
}

var invalidNames = []string{
	"",
}

var invalidPubKeys = []ed25519.PublicKey{
	nil,
	[]byte{},
	make([]byte, ed25519.PublicKeySize-1),
	make([]byte, ed25519.PublicKeySize+1),
}

func TestRemoveTopicCommand(t *testing.T) {
	t.Run("invalid names produce errors", func(t *testing.T) {
		for _, name := range invalidNames {
			_, err := RemoveTopicCommand(name)
			if err == nil {
				t.Fatalf("got no error with name: %s", name)
			}
		}
	})

	t.Run("expected command is created", func(t *testing.T) {
		topic := "some-topic"

		cmd, err := RemoveTopicCommand(topic)
		if err != nil {
			t.Fatalf("failed to create command: %v", err)
		}

		expectedLength := 1 + e4crypto.HashLen
		if l := len(cmd); l != expectedLength {
			t.Fatalf("invalid command length, got %d, wanted %d", l, expectedLength)
		}

		expectedCmd := make([]byte, 0, expectedLength)
		expectedCmd = append(expectedCmd, RemoveTopic.ToByte())
		expectedCmd = append(expectedCmd, e4crypto.HashTopic(topic)...)

		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestResetTopicsCommand(t *testing.T) {
	t.Run("expected command is created", func(t *testing.T) {
		cmd, err := ResetTopicsCommand()
		if err != nil {
			t.Fatalf("failed to created command: %v", err)
		}

		expectedLength := 1
		if l := len(cmd); l != expectedLength {
			t.Fatalf("invalid command length, got %d, wanted %d", l, expectedLength)
		}

		expectedCmd := []byte{ResetTopics.ToByte()}
		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestSetIDKeyCommand(t *testing.T) {
	t.Run("invalid keys return errors", func(t *testing.T) {
		for _, k := range invalidKeys {
			_, err := SetIDKeyCommand(k)
			if err == nil {
				t.Fatalf("got no error with key %v", k)
			}
		}
	})

	t.Run("expected command is created", func(t *testing.T) {
		expectedKey := e4crypto.RandomKey()
		cmd, err := SetIDKeyCommand(expectedKey)
		if err != nil {
			t.Fatalf("failed to create command: %v", err)
		}

		expectedLength := 1 + e4crypto.KeyLen
		if l := len(cmd); l != expectedLength {
			t.Fatalf("invalid command length, got %d, wanted %d", l, expectedLength)
		}

		expectedCmd := make([]byte, 0, expectedLength)
		expectedCmd = append(expectedCmd, SetIDKey.ToByte())
		expectedCmd = append(expectedCmd, expectedKey...)
		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestSetTopicKeyCommand(t *testing.T) {
	t.Run("invalid keys produce errors", func(t *testing.T) {
		for _, k := range invalidKeys {
			_, err := SetTopicKeyCommand(k, "some-topic")
			if err == nil {
				t.Fatalf("got no error with key %v", k)
			}
		}
	})

	t.Run("invalid names produce errors", func(t *testing.T) {
		validKey := e4crypto.RandomKey()
		for _, name := range invalidNames {
			_, err := SetTopicKeyCommand(validKey, name)
			if err == nil {
				t.Fatalf("got no error with name: %s", name)
			}
		}
	})

	t.Run("expected command is created", func(t *testing.T) {
		expectedKey := e4crypto.RandomKey()
		expectedTopic := "some-topic"
		cmd, err := SetTopicKeyCommand(expectedKey, expectedTopic)
		if err != nil {
			t.Fatalf("failed to create command: %v", err)
		}

		expectedLength := 1 + e4crypto.KeyLen + e4crypto.HashLen
		if l := len(cmd); l != expectedLength {
			t.Fatalf("invalid command length, got %d, wanted %d", l, expectedLength)
		}

		expectedCmd := make([]byte, 0, expectedLength)
		expectedCmd = append(expectedCmd, SetTopicKey.ToByte())
		expectedCmd = append(expectedCmd, expectedKey...)
		expectedCmd = append(expectedCmd, e4crypto.HashTopic(expectedTopic)...)
		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestRemovePubKeyCommand(t *testing.T) {
	t.Run("invalid names produce errors", func(t *testing.T) {
		for _, name := range invalidNames {
			_, err := RemovePubKeyCommand(name)
			if err == nil {
				t.Fatalf("got no error with name: %s", name)
			}
		}
	})

	t.Run("expected command is created", func(t *testing.T) {
		expectedName := "some-name"
		cmd, err := RemovePubKeyCommand(expectedName)
		if err != nil {
			t.Fatalf("failed to create command: %v", err)
		}

		expectedLength := 1 + e4crypto.IDLen
		if l := len(cmd); l != expectedLength {
			t.Fatalf("invalid command length, got %d, wanted %d", l, expectedLength)
		}

		expectedCmd := make([]byte, 0, expectedLength)
		expectedCmd = append(expectedCmd, RemovePubKey.ToByte())
		expectedCmd = append(expectedCmd, e4crypto.HashIDAlias(expectedName)...)
		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestResetPubKeysCommand(t *testing.T) {
	t.Run("expected command is created", func(t *testing.T) {
		cmd, err := ResetPubKeysCommand()
		if err != nil {
			t.Fatalf("failed to created command: %v", err)
		}

		expectedLength := 1
		if l := len(cmd); l != expectedLength {
			t.Fatalf("invalid command length, got %d, wanted %d", l, expectedLength)
		}

		expectedCmd := []byte{ResetPubKeys.ToByte()}
		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestSetPubKeyCommand(t *testing.T) {
	t.Run("invalid keys produce errors", func(t *testing.T) {
		for _, k := range invalidPubKeys {
			_, err := SetPubKeyCommand(k, "some-name")
			if err == nil {
				t.Fatalf("got no error with key %v", k)
			}
		}
	})

	t.Run("invalid names produce errors", func(t *testing.T) {
		validKey, _, err := ed25519.GenerateKey((rand.Reader))
		if err != nil {
			t.Fatalf("failed to generate public key: %v", err)
		}

		for _, name := range invalidNames {
			_, err := SetPubKeyCommand(validKey, name)
			if err == nil {
				t.Fatalf("got no error with name: %s", name)
			}
		}
	})

	t.Run("expected command is created", func(t *testing.T) {
		expectedKey, _, err := ed25519.GenerateKey((rand.Reader))
		if err != nil {
			t.Fatalf("failed to generate public key: %v", err)
		}

		expectedName := "some-name"
		cmd, err := SetPubKeyCommand(expectedKey, expectedName)
		if err != nil {
			t.Fatalf("failed to create command: %v", err)
		}

		expectedLength := 1 + ed25519.PublicKeySize + e4crypto.IDLen
		if l := len(cmd); l != expectedLength {
			t.Fatalf("invalid command length, got %d, wanted %d", l, expectedLength)
		}

		expectedCmd := make([]byte, 0, expectedLength)
		expectedCmd = append(expectedCmd, SetPubKey.ToByte())
		expectedCmd = append(expectedCmd, expectedKey...)
		expectedCmd = append(expectedCmd, e4crypto.HashIDAlias(expectedName)...)
		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestToByte(t *testing.T) {
	t.Run("ToByte() returns 255 for out of range commands", func(t *testing.T) {
		if UnknownCommand.ToByte() != 255 {
			t.Fatalf("expected unknown command byte to be %d, got %d", 255, UnknownCommand.ToByte())
		}
	})
}
