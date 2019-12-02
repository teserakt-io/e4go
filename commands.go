package e4go

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
	"errors"
	"fmt"

	"golang.org/x/crypto/ed25519"

	e4crypto "github.com/teserakt-io/e4go/crypto"
)

// Command is a command sent by C2 to a client. This is a sequence of bytes, starting from a Command, followed by the command arguments.
// Such command message must then be protected using the client key, before being passed to the client's Unprotect() method. The command will
// then be unprotected, and processed.
type Command int

// List of supported commands
const (
	// RemoveTopic command allows to remove a topic key from the client.
	// It expects a topic hash as argument
	RemoveTopic Command = iota
	// ResetTopics allows to clear out all the topics on a client.
	// It doesn't have any argument
	ResetTopics
	// SetIDKey allows to set the private key of a client.
	// It expects a key as argument
	SetIDKey
	// SetTopicKey allows to add a topic key on the client.
	// It takes a key, followed by a topic hash as arguments.
	SetTopicKey
	// RemovePubKey allows to remove a public key from the client.
	// It takes the ID to be removed as argument
	RemovePubKey
	// ResetPubKeys removes all public keys stored on the client.
	// It expects no argument
	ResetPubKeys
	// SetPubKey allows to set a public key on the client.
	// It takes a public key, followed by an ID as arguments.
	SetPubKey

	// UnknownCommand must stay the last element. It's used to
	// know if a Command is out of range
	UnknownCommand
)

var (
	// ErrInvalidCommand is returned when trying to process an unsupported command
	ErrInvalidCommand = errors.New("invalid command")
)

// ToByte converts a command into its byte representation
// A value of 255 is returned when the command is out of range
func (c Command) ToByte() byte {
	if c < RemoveTopic || c >= UnknownCommand {
		return 255
	}
	return byte(c)
}

// processCommand will attempt to parse given command
// and extract arguments to call expected Client method
func processCommand(client Client, payload []byte) error {
	cmd, blob := payload[0], payload[1:]

	switch Command(cmd) {
	case RemoveTopic:
		if len(blob) != e4crypto.HashLen {
			return errors.New("invalid RemoveTopic length")
		}
		return client.removeTopic(blob)

	case ResetTopics:
		if len(blob) != 0 {
			return errors.New("invalid ResetTopics length")
		}
		return client.resetTopics()

	case SetIDKey:
		if len(blob) != e4crypto.KeyLen {
			return errors.New("invalid SetIDKey length")
		}
		return client.setIDKey(blob)

	case SetTopicKey:
		if len(blob) != e4crypto.KeyLen+e4crypto.HashLen {
			return errors.New("invalid SetTopicKey length")
		}
		return client.setTopicKey(blob[:e4crypto.KeyLen], blob[e4crypto.KeyLen:])

	case RemovePubKey:
		if len(blob) != e4crypto.IDLen {
			return errors.New("invalid RemovePubKey length")
		}
		return client.removePubKey(blob)

	case ResetPubKeys:
		if len(blob) != 0 {
			return errors.New("invalid ResetPubKeys length")
		}
		return client.resetPubKeys()

	case SetPubKey:
		if len(blob) != ed25519.PublicKeySize+e4crypto.IDLen {
			return errors.New("invalid SetPubKey length")
		}
		return client.setPubKey(blob[:ed25519.PublicKeySize], blob[ed25519.PublicKeySize:])

	default:
		return ErrInvalidCommand
	}
}

// CmdRemoveTopic creates a command to remove the key
// associated with the topic, from the client
func CmdRemoveTopic(topic string) ([]byte, error) {
	if len(topic) == 0 {
		return nil, errors.New("topic must not be empty")
	}

	cmd := append([]byte{RemoveTopic.ToByte()}, e4crypto.HashTopic(topic)...)

	return cmd, nil
}

// CmdResetTopics creates a command to remove all topic keys stored on the client
func CmdResetTopics() ([]byte, error) {
	return []byte{ResetTopics.ToByte()}, nil
}

// CmdSetIDKey creates a command to set the client private key to the given key
func CmdSetIDKey(key []byte) ([]byte, error) {
	if keyLen := len(key); keyLen != e4crypto.KeyLen {
		return nil, fmt.Errorf("invalid key length, got %d, wanted %d", keyLen, e4crypto.KeyLen)
	}

	cmd := append([]byte{SetIDKey.ToByte()}, key...)

	return cmd, nil
}

// CmdSetTopicKey creates a command to set the given
// topic key and its corresponding topic, on the client
func CmdSetTopicKey(topicKey []byte, topic string) ([]byte, error) {
	if g, w := len(topicKey), e4crypto.KeyLen; g != w {
		return nil, fmt.Errorf("invalid key length, got %d, wanted %d", g, w)
	}

	if len(topic) == 0 {
		return nil, errors.New("topic must not be empty")
	}

	cmd := append([]byte{SetTopicKey.ToByte()}, topicKey...)
	cmd = append(cmd, e4crypto.HashTopic(topic)...)

	return cmd, nil
}

// CmdRemovePubKey creates a command to remove the public key identified by given name from the client
func CmdRemovePubKey(name string) ([]byte, error) {
	if len(name) == 0 {
		return nil, errors.New("name must not be empty")
	}

	cmd := append([]byte{RemovePubKey.ToByte()}, e4crypto.HashIDAlias(name)...)

	return cmd, nil
}

// CmdResetPubKeys creates a command to removes all public keys from the client
func CmdResetPubKeys() ([]byte, error) {
	return []byte{ResetPubKeys.ToByte()}, nil
}

// CmdSetPubKey creates a command to set a given public key,
// identified by given name on the client
func CmdSetPubKey(pubKey ed25519.PublicKey, name string) ([]byte, error) {
	if g, w := len(pubKey), ed25519.PublicKeySize; g != w {
		return nil, fmt.Errorf("invalid public key length, got %d, wanted %d", g, w)
	}

	if len(name) == 0 {
		return nil, errors.New("name must not be empty")
	}

	cmd := append([]byte{SetPubKey.ToByte()}, pubKey...)
	cmd = append(cmd, e4crypto.HashIDAlias(name)...)

	return cmd, nil
}
