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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"

	e4crypto "github.com/teserakt-io/e4go/crypto"
)

// PubKeyMaterial extends the ClientKey and PubKeyStore interfaces for public key implementations
type PubKeyMaterial interface {
	KeyMaterial
	PubKeyStore
	PublicKey() ed25519.PublicKey
}

// pubKeyMaterial implements PubKeyMaterial to work with public e4 client key
// and PubKeyStore to holds public key needed to verify message signatures
type pubKeyMaterial struct {
	PrivateKey ed25519.PrivateKey           `json:"privateKey,omitempty"`
	SignerID   []byte                       `json:"signerID,omitempty"`
	C2PubKey   e4crypto.Curve25519PublicKey `json:"c2PubKey,omitempty"`
	PubKeys    map[string]ed25519.PublicKey `json:"pubKeys,omitempty"`

	mutex     sync.RWMutex
	sharedKey []byte
}

var _ PubKeyMaterial = (*pubKeyMaterial)(nil)
var _ json.Marshaler = (*pubKeyMaterial)(nil)

// NewPubKeyMaterial creates a new KeyMaterial to work with public e4 client key
func NewPubKeyMaterial(signerID []byte, privateKey ed25519.PrivateKey, c2PubKey e4crypto.Curve25519PublicKey) (PubKeyMaterial, error) {
	if err := e4crypto.ValidateID(signerID); err != nil {
		return nil, fmt.Errorf("invalid signerID: %v", err)
	}

	if err := e4crypto.ValidateEd25519PrivKey(privateKey); err != nil {
		return nil, fmt.Errorf("invalid private key: %v", err)
	}

	if err := e4crypto.ValidateCurve25519PubKey(c2PubKey); err != nil {
		return nil, fmt.Errorf("invalid c2 public key: %v", err)
	}

	k := &pubKeyMaterial{
		PubKeys: make(map[string]ed25519.PublicKey),
	}

	k.C2PubKey = make([]byte, len(c2PubKey))
	copy(k.C2PubKey, c2PubKey)

	k.PrivateKey = make([]byte, len(privateKey))
	copy(k.PrivateKey, privateKey)

	if err := k.updateSharedKey(); err != nil {
		return nil, err
	}

	k.SignerID = make([]byte, len(signerID))
	copy(k.SignerID, signerID)

	return k, nil
}

// NewRandomPubKeyMaterial creates a new PubKeyMaterial key from a random ed25519 key
func NewRandomPubKeyMaterial(signerID []byte, c2PubKey e4crypto.Curve25519PublicKey) (PubKeyMaterial, error) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return NewPubKeyMaterial(signerID, privateKey, c2PubKey)
}

// Protect will encrypt and sign the payload with the private key and returns it, or an error if it fail
func (k *pubKeyMaterial) ProtectMessage(payload []byte, topicKey TopicKey) ([]byte, error) {
	timestamp := make([]byte, e4crypto.TimestampLen)
	binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().Unix()))

	ct, err := e4crypto.Encrypt(topicKey, timestamp, payload)
	if err != nil {
		return nil, err
	}

	protected, err := e4crypto.Sign(k.SignerID, k.PrivateKey, timestamp, ct)
	if err != nil {
		return nil, err
	}

	protectedLen := e4crypto.TimestampLen + e4crypto.IDLen + len(payload) + e4crypto.TagLen + ed25519.SignatureSize
	if protectedLen != len(protected) {
		return nil, e4crypto.ErrInvalidProtectedLen
	}

	return protected, nil
}

// UnprotectMessage attempts to decrypt the given protected cipher using the given topicKey.
func (k *pubKeyMaterial) UnprotectMessage(protected []byte, topicKey TopicKey) ([]byte, error) {
	if len(protected) <= e4crypto.TimestampLen+ed25519.SignatureSize {
		return nil, e4crypto.ErrInvalidProtectedLen
	}

	// first check timestamp
	timestamp := protected[:e4crypto.TimestampLen]
	if err := e4crypto.ValidateTimestamp(timestamp); err != nil {
		return nil, err
	}

	// then check signature
	signerID := protected[e4crypto.TimestampLen : e4crypto.TimestampLen+e4crypto.IDLen]
	signed := protected[:len(protected)-ed25519.SignatureSize]
	sig := protected[len(protected)-ed25519.SignatureSize:]

	pubkey, err := k.GetPubKey(signerID)
	if err != nil {
		return nil, err
	}

	if !ed25519.Verify(ed25519.PublicKey(pubkey), signed, sig) {
		return nil, e4crypto.ErrInvalidSignature
	}

	ct := protected[e4crypto.TimestampLen+e4crypto.IDLen : len(protected)-ed25519.SignatureSize]

	// finally decrypt
	pt, err := e4crypto.Decrypt(topicKey, timestamp, ct)
	if err != nil {
		return nil, err
	}

	return pt, nil
}

// UnprotectCommand attempt to decrypt a client command from the given protected cipher.
// It will use the material's private key and the c2 public key to create the required symmetric key
func (k *pubKeyMaterial) UnprotectCommand(protected []byte) ([]byte, error) {
	if err := e4crypto.ValidateSymKey(k.sharedKey); err != nil {
		return nil, fmt.Errorf("invalid shared key: %v", err)
	}

	return e4crypto.UnprotectSymKey(protected, k.sharedKey)
}

// AddPubKey store the given id and key in internal storage
// It is safe for concurrent access
func (k *pubKeyMaterial) AddPubKey(id []byte, pubKey ed25519.PublicKey) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if err := e4crypto.ValidateEd25519PubKey(pubKey); err != nil {
		return err
	}

	k.PubKeys[hex.EncodeToString(id)] = pubKey

	return nil
}

// removePubKey removes the key associated to id on the pubKeyMateriel
// It returns an error if no key can be found with the given id
func (k *pubKeyMaterial) RemovePubKey(id []byte) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	sid := hex.EncodeToString(id)
	_, exists := k.PubKeys[sid]
	if !exists {
		return fmt.Errorf("no public key exists for id: %s", id)
	}

	delete(k.PubKeys, sid)

	return nil
}

// ResetPubKeys removes all public keys stored on the pubKeyMaterial
func (k *pubKeyMaterial) ResetPubKeys() {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	// The Go compiler in Go1.12 and above recognizes the map clearing idiom
	// and makes that very fast, but also it'll alleviate garbage collection pressure.
	// so instead of k.PubKeys = make(map[string][]byte), use:
	for key := range k.PubKeys {
		delete(k.PubKeys, key)
	}
}

// GetPubKeys return a map of stored pubKeys, indexed by their hex encoded ids
func (k *pubKeyMaterial) GetPubKeys() map[string]ed25519.PublicKey {
	k.mutex.RLock()
	defer k.mutex.RUnlock()

	return k.PubKeys
}

// GetPubKey return a pubKey associated to given ID, or ErrPubKeyNotFound
// when it doesn't exists
func (k *pubKeyMaterial) GetPubKey(id []byte) (ed25519.PublicKey, error) {
	sid := hex.EncodeToString(id)

	key, ok := k.PubKeys[sid]
	if !ok {
		return nil, ErrPubKeyNotFound
	}

	return key, nil
}

// SetKey will validate the given key and copy it into the pubKeyMaterial key when valid
func (k *pubKeyMaterial) SetKey(key []byte) error {
	if err := e4crypto.ValidateEd25519PrivKey(key); err != nil {
		return err
	}

	sk := make([]byte, len(key))
	copy(sk, key)

	k.PrivateKey = sk
	if err := k.updateSharedKey(); err != nil {
		return err
	}

	return nil
}

func (k *pubKeyMaterial) SetC2PubKey(c2PubKey e4crypto.Curve25519PublicKey) error {
	if err := e4crypto.ValidateCurve25519PubKey(c2PubKey); err != nil {
		return err
	}

	k.C2PubKey = c2PubKey
	if err := k.updateSharedKey(); err != nil {
		return err
	}

	return nil
}

// MarshalJSON  will infer the key type in the marshalled json data
// to be able to know which key to instantiate when unmarshalling back
func (k *pubKeyMaterial) MarshalJSON() ([]byte, error) {
	// we have to use a temporary intermediate struct here as
	// passing directly k to KeyData would cause an infinite loop of MarshalJSON calls
	jsonKey := &jsonKey{
		KeyType: pubKeyMaterialType,
		KeyData: struct {
			PrivateKey ed25519.PrivateKey
			SignerID   []byte
			C2PubKey   []byte
			PubKeys    map[string]ed25519.PublicKey
		}{
			PrivateKey: k.PrivateKey,
			SignerID:   k.SignerID,
			C2PubKey:   k.C2PubKey,
			PubKeys:    k.PubKeys,
		},
	}

	return json.Marshal(jsonKey)
}

// PublicKey returns the public key of the keyMaterial
func (k *pubKeyMaterial) PublicKey() ed25519.PublicKey {
	publicPart := k.PrivateKey.Public()
	publicKey, ok := publicPart.(ed25519.PublicKey)
	if !ok {
		panic(fmt.Sprintf("%T is invalid for public key, wanted ed25519.PublicKey", publicPart))
	}

	return publicKey
}

func (k *pubKeyMaterial) updateSharedKey() error {
	curvePrivateKey := e4crypto.PrivateEd25519KeyToCurve25519(k.PrivateKey)
	sharedKey, err := curve25519.X25519(curvePrivateKey, k.C2PubKey)
	if err != nil {
		return fmt.Errorf("curve25519 X25519 failed: %v", err)
	}

	k.sharedKey = e4crypto.Sha3Sum256(sharedKey)[:e4crypto.KeyLen]

	return nil
}

func (k *pubKeyMaterial) validate() error {
	if err := e4crypto.ValidateID(k.SignerID); err != nil {
		return err
	}
	if err := e4crypto.ValidateEd25519PrivKey(k.PrivateKey); err != nil {
		return err
	}
	if err := e4crypto.ValidateCurve25519PubKey(k.C2PubKey); err != nil {
		return err
	}
	for id, pubKey := range k.PubKeys {
		decodedID, err := hex.DecodeString(id)
		if err != nil {
			return err
		}

		if err := e4crypto.ValidateID(decodedID); err != nil {
			return err
		}
		if err := e4crypto.ValidateEd25519PubKey(pubKey); err != nil {
			return err
		}
	}

	return nil
}
