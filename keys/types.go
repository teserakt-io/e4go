package keys

import (
	"errors"
)

var (
	// ErrInvalidSignature occurs when a signature verification fails.
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrPubKeyNotFound occurs when a public key is missing when verifying a signature.
	ErrPubKeyNotFound = errors.New("signer public key not found")
)

// TopicKey defines a custom type for topic keys, avoiding mixing them
// with other keys on the ProtectMessage and UnprotectMessage functions
type TopicKey []byte

// ClientKey defines an interface for E4 client key implementations
type ClientKey interface {
	Validate() error
	ProtectMessage(payload []byte, topicKey TopicKey) ([]byte, error)
	UnprotectMessage(protected []byte, topicKey TopicKey) ([]byte, error)
	UnprotectCommand(protected []byte) ([]byte, error)
	SetKey(key []byte) error
	MarshalJSON() ([]byte, error)
}

// PubKeyStore interface defines methods to interact with a public key storage
type PubKeyStore interface {
	AddPubKey(id string, key []byte) error
	RemovePubKey(id string) error
	ResetPubKeys()
}
