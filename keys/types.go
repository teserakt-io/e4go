package keys

import (
	"errors"
)

var (
	// ErrInvalidSignature occurs when a signature verification fails
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrPubKeyNotFound occurs when a public key is missing when verifying a signature
	ErrPubKeyNotFound = errors.New("signer public key not found")
)

// TopicKey defines a custom type for topic keys, avoiding mixing them
// with other keys on the ProtectMessage and UnprotectMessage functions
type TopicKey []byte

// KeyMaterial defines an interface for E4 client key implementations
type KeyMaterial interface {
	// ProtectMessage encrypt given payload using the topicKey
	// and returns the protected cipher, or an error
	ProtectMessage(payload []byte, topicKey TopicKey) ([]byte, error)
	// UnprotectMessage decrypt the given cipher using the topicKey
	// and returns the clear payload, or an error
	UnprotectMessage(protected []byte, topicKey TopicKey) ([]byte, error)
	// UnprotectCommand decrypt the given protected command using the key material private key
	// and returns the command, or an error
	UnprotectCommand(protected []byte) ([]byte, error)
	// SetKey sets the material private key, or return an error when the key is invalid
	SetKey(key []byte) error
	// MarshalJSON marshal the key material into json
	MarshalJSON() ([]byte, error)
}

// PubKeyStore interface defines methods to interact with a public key storage
type PubKeyStore interface {
	AddPubKey(id []byte, key []byte) error
	GetPubKey(id []byte) ([]byte, error)
	GetPubKeys() map[string][]byte
	RemovePubKey(id []byte) error
	ResetPubKeys()
}
