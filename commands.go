package e4go

import (
	"errors"

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
