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

// Package keys holds E4 key material implementations.
package keys

import (
	"errors"

	"golang.org/x/crypto/ed25519"
)

var (

	// ErrPubKeyNotFound occurs when a public key is missing when verifying a signature
	ErrPubKeyNotFound = errors.New("signer public key not found")
)

// TopicKey defines a custom type for topic keys, avoiding mixing them
// with other keys on the ProtectMessage and UnprotectMessage functions
type TopicKey []byte

// KeyMaterial defines an interface for E4 client key implementations
// It holds the client private key, and allows to defines how messages will be
// encrypted or decrypted, and how commands will be unprotected.
// A KeyMaterial must also marshal into a jsonKey, allowing the client to properly
// store and load the key material
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
// A key material implementing a PubKeyStore enable the client to receive any of the
// pubKey's commands. When the KeyMaterial doesn't implement it, such commands will return
// a ErrUnsupportedOperation error.
type PubKeyStore interface {
	// AddPubKey allows to add a public key to the store, identified by ID.
	// If a key already exists with this ID, it will be replaced.
	AddPubKey(id []byte, key ed25519.PublicKey) error
	// GetPubKey returns the public key associated to the ID.
	// ErrPubKeyNotFound is returned when it cannot be found.
	GetPubKey(id []byte) (ed25519.PublicKey, error)
	// GetPubKeys returns all stored public keys, in a ID indexed map.
	GetPubKeys() map[string]ed25519.PublicKey
	// RemovePubKey removes a public key from the store by its ID, or returns
	// an error if it doesn't exists.
	RemovePubKey(id []byte) error
	// ResetPubKeys removes all public keys stored.
	ResetPubKeys()
}
