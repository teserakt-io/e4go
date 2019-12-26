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

package e4

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ed25519"

	e4crypto "github.com/teserakt-io/e4go/crypto"
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

func TestCmdRemoveTopic(t *testing.T) {
	t.Run("invalid names produce errors", func(t *testing.T) {
		for _, name := range invalidNames {
			_, err := CmdRemoveTopic(name)
			if err == nil {
				t.Fatalf("got no error with name: %s", name)
			}
		}
	})

	t.Run("expected command is created", func(t *testing.T) {
		topic := "some-topic"

		cmd, err := CmdRemoveTopic(topic)
		if err != nil {
			t.Fatalf("failed to create command: %v", err)
		}

		if got, want := len(cmd), 1+e4crypto.HashLen; got != want {
			t.Fatalf("invalid command length, got %d, wanted %d", got, want)
		}

		expectedCmd := append([]byte{RemoveTopic.ToByte()}, e4crypto.HashTopic(topic)...)
		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestCmdResetTopics(t *testing.T) {
	t.Run("expected command is created", func(t *testing.T) {
		cmd, err := CmdResetTopics()
		if err != nil {
			t.Fatalf("failed to created command: %v", err)
		}

		if got, want := len(cmd), 1; got != want {
			t.Fatalf("invalid command length, got %d, wanted %d", got, want)
		}

		expectedCmd := []byte{ResetTopics.ToByte()}
		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestCmdSetIDKey(t *testing.T) {
	t.Run("invalid keys return errors", func(t *testing.T) {
		for _, k := range invalidKeys {
			_, err := CmdSetIDKey(k)
			if err == nil {
				t.Fatalf("got no error with key %v", k)
			}
		}
	})

	t.Run("expected command is created", func(t *testing.T) {
		expectedKey := e4crypto.RandomKey()
		cmd, err := CmdSetIDKey(expectedKey)
		if err != nil {
			t.Fatalf("failed to create command: %v", err)
		}

		if got, want := len(cmd), 1+e4crypto.KeyLen; got != want {
			t.Fatalf("invalid command length, got %d, wanted %d", got, want)
		}

		expectedCmd := append([]byte{SetIDKey.ToByte()}, expectedKey...)
		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestCmdSetTopicKey(t *testing.T) {
	t.Run("invalid keys produce errors", func(t *testing.T) {
		for _, k := range invalidKeys {
			_, err := CmdSetTopicKey(k, "some-topic")
			if err == nil {
				t.Fatalf("got no error with key %v", k)
			}
		}
	})

	t.Run("invalid names produce errors", func(t *testing.T) {
		validKey := e4crypto.RandomKey()
		for _, name := range invalidNames {
			_, err := CmdSetTopicKey(validKey, name)
			if err == nil {
				t.Fatalf("got no error with name: %s", name)
			}
		}
	})

	t.Run("expected command is created", func(t *testing.T) {
		expectedKey := e4crypto.RandomKey()
		expectedTopic := "some-topic"
		cmd, err := CmdSetTopicKey(expectedKey, expectedTopic)
		if err != nil {
			t.Fatalf("failed to create command: %v", err)
		}

		if got, want := len(cmd), 1+e4crypto.KeyLen+e4crypto.HashLen; got != want {
			t.Fatalf("invalid command length, got %d, wanted %d", got, want)
		}

		expectedCmd := append([]byte{SetTopicKey.ToByte()}, expectedKey...)
		expectedCmd = append(expectedCmd, e4crypto.HashTopic(expectedTopic)...)
		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestCmdRemovePubKey(t *testing.T) {
	t.Run("invalid names produce errors", func(t *testing.T) {
		for _, name := range invalidNames {
			_, err := CmdRemovePubKey(name)
			if err == nil {
				t.Fatalf("got no error with name: %s", name)
			}
		}
	})

	t.Run("expected command is created", func(t *testing.T) {
		expectedName := "some-name"
		cmd, err := CmdRemovePubKey(expectedName)
		if err != nil {
			t.Fatalf("failed to create command: %v", err)
		}

		if got, want := len(cmd), 1+e4crypto.IDLen; got != want {
			t.Fatalf("invalid command length, got %d, wanted %d", got, want)
		}

		expectedCmd := append([]byte{RemovePubKey.ToByte()}, e4crypto.HashIDAlias(expectedName)...)
		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestCmdResetPubKeys(t *testing.T) {
	t.Run("expected command is created", func(t *testing.T) {
		cmd, err := CmdResetPubKeys()
		if err != nil {
			t.Fatalf("failed to created command: %v", err)
		}

		if got, want := len(cmd), 1; got != want {
			t.Fatalf("invalid command length, got %d, wanted %d", got, want)
		}

		expectedCmd := []byte{ResetPubKeys.ToByte()}
		if !bytes.Equal(cmd, expectedCmd) {
			t.Fatalf("invalid command, got %v, wanted %v", cmd, expectedCmd)
		}
	})
}

func TestCmdSetPubKey(t *testing.T) {
	t.Run("invalid keys produce errors", func(t *testing.T) {
		for _, k := range invalidPubKeys {
			_, err := CmdSetPubKey(k, "some-name")
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
			_, err := CmdSetPubKey(validKey, name)
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
		cmd, err := CmdSetPubKey(expectedKey, expectedName)
		if err != nil {
			t.Fatalf("failed to create command: %v", err)
		}

		if got, want := len(cmd), 1+ed25519.PublicKeySize+e4crypto.IDLen; got != want {
			t.Fatalf("invalid command length, got %d, wanted %d", got, want)
		}

		expectedCmd := append([]byte{SetPubKey.ToByte()}, expectedKey...)
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
