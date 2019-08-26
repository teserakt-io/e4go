package e4common

import (
	"errors"

	e4crypto "gitlab.com/teserakt/e4common/crypto"
	"golang.org/x/crypto/ed25519"
)

// Command is a command sent by C2 to a client
type Command int

// List of supported commands
const (
	RemoveTopic Command = iota
	ResetTopics
	SetIDKey
	SetTopicKey
	RemovePubKey
	ResetPubKeys
	SetPubKey

	UnknownCommand
)

// ErrInvalidCommand is returned when trying to process an unsupported command
var ErrInvalidCommand = errors.New("invalid command")

// ToByte converts a command into its byte representation
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
