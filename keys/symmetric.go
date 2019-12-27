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

package keys

import (
	"encoding/json"
	"fmt"

	e4crypto "github.com/teserakt-io/e4go/crypto"
)

// SymKeyMaterial extends the KeyMaterial interface for symmetric key implementations
type SymKeyMaterial interface {
	KeyMaterial
}

// symKeyMaterial implements SymKeyMaterial
type symKeyMaterial struct {
	Key []byte `json:"key,omitempty"`
}

var _ SymKeyMaterial = (*symKeyMaterial)(nil)

// NewSymKeyMaterial creates a new SymKeyMaterial
func NewSymKeyMaterial(key []byte) (SymKeyMaterial, error) {
	if err := e4crypto.ValidateSymKey(key); err != nil {
		return nil, fmt.Errorf("failed to validate sym key: %v", err)
	}

	s := &symKeyMaterial{}

	s.Key = make([]byte, len(key))
	copy(s.Key, key)

	return s, nil
}

// NewRandomSymKeyMaterial creates a new SymKeyMaterial from random value
func NewRandomSymKeyMaterial() (SymKeyMaterial, error) {
	return NewSymKeyMaterial(e4crypto.RandomKey())
}

// Protect will encrypt payload with the key and returns it, or an error if it fail
func (k *symKeyMaterial) ProtectMessage(payload []byte, topicKey TopicKey) ([]byte, error) {
	protected, err := e4crypto.ProtectSymKey(payload, topicKey)
	if err != nil {
		return nil, err
	}

	return protected, nil
}

// UnprotectCommand attempts to decrypt a client command from given protected cipher,
// using the material's key
func (k *symKeyMaterial) UnprotectCommand(protected []byte) ([]byte, error) {
	return e4crypto.UnprotectSymKey(protected, k.Key)
}

// UnprotectMessage attempts to decrypt a message from given protected cipher,
// using given topic key
func (k *symKeyMaterial) UnprotectMessage(protected []byte, topicKey TopicKey) ([]byte, error) {
	return e4crypto.UnprotectSymKey(protected, topicKey)
}

// SetKey will validate the given key and copy it into the SymKeyMaterial private key when valid
func (k *symKeyMaterial) SetKey(key []byte) error {
	if err := e4crypto.ValidateSymKey(key); err != nil {
		return err
	}

	sk := make([]byte, len(key))
	copy(sk, key)

	k.Key = sk

	return nil
}

// MarshalJSON  will infer the key type in the marshalled json data
// to be able to know which key to instantiate when unmarshalling back
func (k *symKeyMaterial) MarshalJSON() ([]byte, error) {
	// we have to use a temporary intermediate struct here as
	// passing directly k to KeyData would cause an infinite loop of MarshalJSON calls
	jsonKey := &jsonKey{
		KeyType: symKeyMaterialType,
		KeyData: struct {
			Key []byte
		}{
			Key: k.Key,
		},
	}

	return json.Marshal(jsonKey)
}
