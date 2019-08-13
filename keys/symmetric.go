package keys

import (
	"encoding/json"
	"fmt"

	e4crypto "gitlab.com/teserakt/e4common/crypto"
)

// SymKey extends the ClientKey interface for symmetric key implementations
type SymKey interface {
	ClientKey
}

// SymKey implements ClientKey for a symmetric key
type symKey struct {
	Key []byte
}

var _ SymKey = (*symKey)(nil)

// NewSymKeyFromPassword creates a SymKey from a given password
func NewSymKeyFromPassword(pwd string) (SymKey, error) {
	key, err := e4crypto.DeriveSymKey(pwd)
	if err != nil {
		return nil, err
	}

	return NewSymKey(key)
}

// NewSymKey creates a new SymKey
func NewSymKey(key []byte) (SymKey, error) {
	if err := e4crypto.ValidateSymKey(key); err != nil {
		return nil, fmt.Errorf("failed to validate sym key: %v", err)
	}

	s := &symKey{}

	s.Key = make([]byte, len(key))
	copy(s.Key, key)

	return s, nil
}

// NewRandomSymKey creates a new SymKey from random value
func NewRandomSymKey() (SymKey, error) {
	return NewSymKey(e4crypto.RandomKey())
}

// Protect will encrypt payload with the key and returns it, or an error if it fail.
func (k *symKey) ProtectMessage(payload []byte, topicKey TopicKey) ([]byte, error) {
	protected, err := e4crypto.ProtectSymKey(payload, topicKey)
	if err != nil {
		return nil, err
	}

	return protected, nil
}

func (k *symKey) UnprotectCommand(protected []byte) ([]byte, error) {
	return e4crypto.UnprotectSymKey(protected, k.Key)
}

func (k *symKey) UnprotectMessage(protected []byte, topicKey TopicKey) ([]byte, error) {
	return e4crypto.UnprotectSymKey(protected, topicKey)
}

// SetKey will validate the given key and copy it into the symKey key when valid
func (k *symKey) SetKey(key []byte) error {
	if err := e4crypto.ValidateSymKey(key); err != nil {
		return err
	}

	sk := make([]byte, len(key))
	copy(sk, key)

	k.Key = sk

	return nil
}

// MarshalJSON  will infer the key type in the marshalled json data
// to be able to know which key to instanciate when unmarshalling back.
func (k *symKey) MarshalJSON() ([]byte, error) {
	jsonKey := &jsonKey{
		KeyType: symKeyType,
		KeyData: struct {
			Key []byte
		}{
			Key: k.Key,
		},
	}

	return json.Marshal(jsonKey)
}
