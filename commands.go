package e4common

import (
	"errors"

	e4crypto "gitlab.com/teserakt/e4common/crypto"
	"golang.org/x/crypto/ed25519"
)

// Command is a command sent by C2 to a client.
type Command int

// ...
const (
	RemoveTopic Command = iota
	ResetTopics
	SetIDKey
	SetTopicKey //
	RemovePubKey
	ResetPubKeys
	SetPubKey
)

// ErrInvalidCommand is returned when trying to process an unsupported command
var ErrInvalidCommand = errors.New("invalid command")

// ToByte converts a command into its byte representation
func (c Command) ToByte() byte {
	switch c {
	case RemoveTopic:
		return 0
	case ResetTopics:
		return 1
	case SetIDKey:
		return 2
	case SetTopicKey:
		return 3
	case RemovePubKey:
		return 4
	case ResetPubKeys:
		return 5
	case SetPubKey:
		return 6
	}
	return 255
}

// processCommand will attempt to parse given command
// and extract arguments to call expected Client method.
func processCommand(client Client, command []byte) error {
	switch Command(command[0]) {
	case RemoveTopic:
		if len(command) != e4crypto.HashLen+1 {
			return errors.New("invalid RemoveTopic length")
		}
		return client.RemoveTopic(command[1:])

	case ResetTopics:
		if len(command) != 1 {
			return errors.New("invalid ResetTopics length")
		}
		return client.ResetTopics()

	case SetIDKey:
		if len(command) != e4crypto.KeyLen+1 {
			return errors.New("invalid SetIDKey length")
		}
		return client.SetIDKey(command[1:])

	case SetTopicKey:
		if len(command) != e4crypto.KeyLen+e4crypto.HashLen+1 {
			return errors.New("invalid SetTopicKey length")
		}
		return client.SetTopicKey(command[1:1+e4crypto.KeyLen], command[1+e4crypto.KeyLen:])

	case RemovePubKey:
		if len(command) != e4crypto.IDLen+1 {
			return errors.New("invalid RemovePubKey length")
		}
		return client.RemovePubKey(command[1:])

	case ResetPubKeys:
		if len(command) != 1 {
			return errors.New("invalid ResetPubKeys length")
		}
		return client.ResetPubKeys()

	case SetPubKey:
		if len(command) != ed25519.PublicKeySize+e4crypto.IDLen+1 {
			return errors.New("invalid SetPubKey length")
		}
		return client.SetPubKey(command[1:1+ed25519.PublicKeySize], command[1+ed25519.PublicKeySize:])

	default:
		return ErrInvalidCommand
	}
}
