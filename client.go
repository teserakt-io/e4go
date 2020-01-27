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

// Package e4 provides a e4 client implementation and libraries.
//
// It aims to be quick and easy to integrate in IoT devices applications
// enabling to secure their communications, as well as exposing a way to manage the various keys required.
//
// Protecting and unprotecting messages
//
// Once created, a client provide methods to protect messages before sending them to the broker:
//  protectedMessage, err := client.ProtectMessage([]byte("secret message"), topicKey)
// or unprotecting the messages it receives.
//  originalMessage, err := client.Unprotect([]byte(protectedMessage, topicKey))
//
// ReceivingTopic and client commands
//
// A special topic (called ReceivingTopic) is reserved to communicate protected commands to the client.
// Such commands are used to update the client state, like setting a new key for a topic, or renewing its private key.
// There is nothing particular to be done when receiving a command, just passing its protected form to the Unprotect() method
// and the client will automatically unprotect and process it (thus returning no unprotected message).
// See commands.go for the list of available commands and their respective parameters.
package e4

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	miscreant "github.com/miscreant/miscreant.go"
	"golang.org/x/crypto/ed25519"

	e4crypto "github.com/teserakt-io/e4go/crypto"
	"github.com/teserakt-io/e4go/keys"
)

const (
	idTopicPrefix = "e4/"
)

var (
	// ErrTopicKeyNotFound occurs when a topic key is missing when encryption/decrypting
	ErrTopicKeyNotFound = errors.New("topic key not found")
	// ErrUnsupportedOperation occurs when trying to manipulate client public keys with a ClientKey not supporting it
	ErrUnsupportedOperation = errors.New("this operation is not supported")
)

// Client defines interface for protecting and unprotecting E4 messages and commands
type Client interface {
	// ProtectMessage will encrypt the given payload using the key associated to topic.
	// When the client doesn't have a key for this topic, ErrTopicKeyNotFound will be returned.
	// When no errors, the protected cipher bytes are returned
	ProtectMessage(payload []byte, topic string) ([]byte, error)
	// Unprotect attempts to decrypt the given cipher using the topic key.
	// When the client doesn't have a key for this topic, ErrTopicKeyNotFound will be returned.
	// When no errors, the clear payload bytes are returned, unless the protected message was a client command.
	// Message are client commands when received on the client receiving topic. The command will be processed
	// when unprotecting it, making a nil,nil response indicating a success
	Unprotect(protected []byte, topic string) ([]byte, error)
	// IsReceivingTopic returns true when the given topic is the client receiving topics.
	// Message received from this topics will be protected commands, meant to update the client state
	IsReceivingTopic(topic string) bool
	// GetReceivingTopic returns the receiving topic for this client, which will be used to transmit commands
	// allowing to update the client state, like setting a new private key or adding a new topic key.
	GetReceivingTopic() string

	// setIDKey will set the client's key material private key to the given key
	setIDKey(key []byte) error
	// setPubKey set the public key for the given clientID, if the client key material support it.
	// otherwise, ErrUnsupportedOperation is returned
	setPubKey(key ed25519.PublicKey, clientID []byte) error
	// removePubKey remove the public key for the given clientID, if the client key material support it.
	// otherwise, ErrUnsupportedOperation is returned
	removePubKey(clientID []byte) error
	// resetPubKeys remove all pubKeys from the key material, if it support it.
	// otherwise, ErrUnsupportedOperation is returned
	resetPubKeys() error
	// getPubKeys returns the map of public keys having been set on the client, if the client key material support it.
	// otherwise, ErrUnsupportedOperation is returned
	getPubKeys() (map[string]ed25519.PublicKey, error)
	// setTopicKey set the key for the given topic hash (see crypto.HashTopic to obtain topic hashes).
	// Setting topic keys is required prior being able to communicate over this topic.
	setTopicKey(key, topicHash []byte) error
	// removeTopic will remove the topic key from the client for the given topic hash (see crypto.HashTopic to obtain topic hashes).
	removeTopic(topicHash []byte) error
	// resetTopics will remove all previously set topics from the client.
	resetTopics() error
}

// client implements Client interface
// It holds the client state and is saved to disk for persistent storage
type client struct {
	ID []byte
	// TopicKeys maps a topic hash to a key
	// (slices []byte can't be map keys, converting to strings)
	TopicKeys map[string]keys.TopicKey

	Key keys.KeyMaterial

	ReceivingTopic string

	store io.WriteSeeker
	lock  sync.RWMutex
}

var _ Client = (*client)(nil)

// ClientConfig defines an interface for client configuration
type ClientConfig interface {
	genNewClient(store io.WriteSeeker) (Client, error)
}

// SymIDAndKey defines a configuration to create an E4 client in symmetric key mode
// from an ID and a symmetric key
type SymIDAndKey struct {
	ID  []byte
	Key []byte
}

// SymNameAndPassword defines a configuration to create an E4 client in symmetric key mode
// from a name and a password.
// The password must contains at least 16 characters.
type SymNameAndPassword struct {
	Name     string
	Password string
}

// PubIDAndKey defines a configuration to create an E4 client in public key mode
// from an ID, an ed25519 private key, and a curve25519 public key.
type PubIDAndKey struct {
	ID       []byte
	Key      e4crypto.Ed25519PrivateKey
	C2PubKey e4crypto.Curve25519PublicKey
}

// PubNameAndPassword defines a configuration to create an E4 client in public key mode
// from a name, a password and a curve25519 public key.
// The password must contains at least 16 characters.
type PubNameAndPassword struct {
	Name     string
	Password string
	C2PubKey e4crypto.Curve25519PublicKey
}

var _ ClientConfig = (*SymIDAndKey)(nil)
var _ ClientConfig = (*SymNameAndPassword)(nil)
var _ ClientConfig = (*PubIDAndKey)(nil)
var _ ClientConfig = (*PubNameAndPassword)(nil)

func (ik *SymIDAndKey) genNewClient(store io.WriteSeeker) (Client, error) {
	var newID []byte
	if len(ik.ID) == 0 {
		newID = e4crypto.RandomID()
	} else {
		newID = make([]byte, len(ik.ID))
		copy(newID, ik.ID)
	}

	symKeyMaterial, err := keys.NewSymKeyMaterial(ik.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to created symkey from key: %v", err)
	}

	return newClient(newID, symKeyMaterial, store)
}

func (np *SymNameAndPassword) genNewClient(store io.WriteSeeker) (Client, error) {
	id := e4crypto.HashIDAlias(np.Name)

	key, err := e4crypto.DeriveSymKey(np.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key from password: %v", err)
	}

	symKeyMaterial, err := keys.NewSymKeyMaterial(key)
	if err != nil {
		return nil, fmt.Errorf("failed to created symkey from key: %v", err)
	}

	return newClient(id, symKeyMaterial, store)
}

func (ik *PubIDAndKey) genNewClient(store io.WriteSeeker) (Client, error) {
	var newID []byte
	if len(ik.ID) == 0 {
		newID = e4crypto.RandomID()
	} else {
		newID = make([]byte, len(ik.ID))
		copy(newID, ik.ID)
	}

	pubKeyMaterialKey, err := keys.NewPubKeyMaterial(newID, ik.Key, ik.C2PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create ed25519key from key: %v", err)
	}

	return newClient(newID, pubKeyMaterialKey, store)
}

func (np *PubNameAndPassword) genNewClient(store io.WriteSeeker) (Client, error) {
	id := e4crypto.HashIDAlias(np.Name)

	key, err := e4crypto.Ed25519PrivateKeyFromPassword(np.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to create ed25519 key from password: %v", err)
	}

	pubKeyMaterialKey, err := keys.NewPubKeyMaterial(id, key, np.C2PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create ed25519key from key: %v", err)
	}

	return newClient(id, pubKeyMaterialKey, store)
}

// PubKey returns the ed25519.PublicKey derived from the password
func (np *PubNameAndPassword) PubKey() (e4crypto.Ed25519PublicKey, error) {
	key, err := e4crypto.Ed25519PrivateKeyFromPassword(np.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to create ed25519 key from password: %v", err)
	}

	edKey, ok := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("failed to cast key to ed25519.PublicKey")
	}

	return edKey, nil
}

// NewClient creates a new E4 client, working either in symmetric key mode, or public key mode
// depending the given ClientConfig
//
// config is a ClientConfig, either SymIDAndKey, SymNameAndPassword, PubIDAndKey or PubNameAndPassword
// persistStatePath is the file system path to the file to read and persist the client's state.
func NewClient(config ClientConfig, store io.WriteSeeker) (Client, error) {
	return config.genNewClient(store)
}

// newClient creates a new client, generating a random ID if they are empty
func newClient(id []byte, clientKey keys.KeyMaterial, store io.WriteSeeker) (Client, error) {
	if len(id) == 0 {
		return nil, errors.New("client id must not be empty")
	}

	c := &client{
		Key:            clientKey,
		TopicKeys:      make(map[string]keys.TopicKey),
		ReceivingTopic: TopicForID(id),

		store: store,
	}

	c.ID = make([]byte, len(id))
	copy(c.ID, id)

	log.SetPrefix("e4client\t")

	return c, nil
}

// LoadClient loads a client state from the file system
func LoadClient(store io.ReadWriteSeeker) (Client, error) {
	c := &client{}

	decoder := json.NewDecoder(store)
	err := decoder.Decode(c)
	if err != nil {
		return nil, err
	}

	store.Seek(0, io.SeekStart)

	c.store = store

	return c, nil
}

func (c *client) save() error {
	encoder := json.NewEncoder(c.store)
	err := encoder.Encode(c)
	if err != nil {
		log.Printf("failed to save client: %v", err)
		return err
	}

	c.store.Seek(0, io.SeekStart)

	return nil
}

func (c *client) UnmarshalJSON(data []byte) error {
	m := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("failed to unmarshal client from json: %v", err)
	}

	if rawKey, ok := m["Key"]; ok {
		clientKey, err := keys.FromRawJSON(rawKey)
		if err != nil {
			return fmt.Errorf("failed to unmarshal client key: %v", err)
		}

		c.Key = clientKey
	}

	if rawReceivingTopic, ok := m["ReceivingTopic"]; ok {
		if err := json.Unmarshal(rawReceivingTopic, &c.ReceivingTopic); err != nil {
			return fmt.Errorf("failed to unmarshal client receiving topic: %v", err)
		}
	}

	if rawTopicKeys, ok := m["TopicKeys"]; ok {
		if err := json.Unmarshal(rawTopicKeys, &c.TopicKeys); err != nil {
			return fmt.Errorf("failed to unmarshal client topicKeys: %v", err)
		}
	}

	if rawID, ok := m["ID"]; ok {
		if err := json.Unmarshal(rawID, &c.ID); err != nil {
			return fmt.Errorf("failed to unmarshal client ID: %v", err)
		}
	}

	return nil
}

// ProtectMessage will protect given payload, given
// the client holds a key for the given topic, otherwise
// ErrTopicKeyNotFound will be returned
func (c *client) ProtectMessage(payload []byte, topic string) ([]byte, error) {
	topicHash := hex.EncodeToString(e4crypto.HashTopic(topic))

	c.lock.RLock()
	topicKey, ok := c.TopicKeys[topicHash]
	c.lock.RUnlock()
	if !ok {
		return nil, ErrTopicKeyNotFound
	}

	protected, err := c.Key.ProtectMessage(payload, topicKey)
	if err != nil {
		return nil, err
	}

	return protected, nil
}

// Unprotect will attempt to unprotect the given payload and return the clear message
// The client holds a key for the given topic, otherwise a ErrTopicKeyNotFound error will be returned
//
// In case the protected message is a command (when the topic is identical to the client control topic),
// Unprotect will also process it, returning errors when it is invalid or missing required
// arguments. On success, Unprotecting a command will return nil, nil
func (c *client) Unprotect(protected []byte, topic string) ([]byte, error) {
	if topic == c.ReceivingTopic {
		command, err := c.Key.UnprotectCommand(protected)
		if err != nil {
			return nil, err
		}

		err = processCommand(c, command)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}

	topicHash := e4crypto.HashTopic(topic)
	c.lock.RLock()
	key, ok := c.TopicKeys[hex.EncodeToString(topicHash)]
	c.lock.RUnlock()
	if !ok {
		return nil, ErrTopicKeyNotFound
	}

	message, err := c.Key.UnprotectMessage(protected, key)

	if err == nil {
		return message, nil
	}

	if err != miscreant.ErrNotAuthentic {
		return nil, err
	}

	// Since decryption failed, try the previous key if it exists and not too old.
	hashOfHash := hex.EncodeToString(e4crypto.HashTopic(string(topicHash)))
	topicKeyTs, ok := c.TopicKeys[hashOfHash]
	if !ok {
		return nil, miscreant.ErrNotAuthentic
	}
	if len(topicKeyTs) != e4crypto.KeyLen+e4crypto.TimestampLen {
		return nil, errors.New("invalid old topic key length")
	}
	topicKey := make([]byte, e4crypto.KeyLen)
	copy(topicKey, topicKeyTs[:e4crypto.KeyLen])
	timestamp := topicKeyTs[e4crypto.KeyLen:]
	if err := e4crypto.ValidateTimestampKey(timestamp); err != nil {
		return nil, err
	}

	return c.Key.UnprotectMessage(protected, topicKey)
}

// IsReceivingTopic indicate when the given topic is the receiving topic of the client.
// This means message received on this topic are client commands
func (c *client) IsReceivingTopic(topic string) bool {
	return topic == c.ReceivingTopic
}

// GetReceivingTopic returns the client receiving topic.
func (c *client) GetReceivingTopic() string {
	return c.ReceivingTopic
}

// setTopicKey adds a key to the given topic hash, erasing any previous entry
func (c *client) setTopicKey(key, topicHash []byte) error {
	if err := e4crypto.ValidateTopicHash(topicHash); err != nil {
		return fmt.Errorf("invalid topic hash: %v", err)
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	topicHashHex := hex.EncodeToString(topicHash)

	// Key transition, if a key already exists for this topic
	topicKey, ok := c.TopicKeys[topicHashHex]
	if ok {
		// Only do key transition if the key received is distinct from the current one
		if !bytes.Equal(topicKey, key) {
			hashOfHash := e4crypto.HashTopic(string(topicHash))
			timestamp := make([]byte, e4crypto.TimestampLen)
			binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().Unix()))
			topicKey = append(topicKey, timestamp...)
			c.TopicKeys[hex.EncodeToString(hashOfHash)] = topicKey
		}
	}

	newKey := make([]byte, e4crypto.KeyLen)
	copy(newKey, key)
	c.TopicKeys[topicHashHex] = newKey
	return c.save()
}

// removeTopic removes the key of the given topic hash
func (c *client) removeTopic(topicHash []byte) error {
	if err := e4crypto.ValidateTopicHash(topicHash); err != nil {
		return fmt.Errorf("invalid topic hash: %v", err)
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	delete(c.TopicKeys, hex.EncodeToString(topicHash))

	// Delete key kept for key transition, if any
	hashOfHash := e4crypto.HashTopic(string(topicHash))
	delete(c.TopicKeys, hex.EncodeToString(hashOfHash))

	return c.save()
}

// resetTopics removes all topic keys
func (c *client) resetTopics() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.TopicKeys = make(map[string]keys.TopicKey)
	return c.save()
}

// getPubKeys return the list of public keys stored on the client
func (c *client) getPubKeys() (map[string]ed25519.PublicKey, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	pkStore, ok := c.Key.(keys.PubKeyStore)
	if !ok {
		return nil, ErrUnsupportedOperation
	}

	return pkStore.GetPubKeys(), nil
}

// setPubKey adds a key to the given clientID, erasing any previous entry
func (c *client) setPubKey(key ed25519.PublicKey, clientID []byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	pkStore, ok := c.Key.(keys.PubKeyStore)
	if !ok {
		return ErrUnsupportedOperation
	}

	if err := e4crypto.ValidateID(clientID); err != nil {
		return fmt.Errorf("invalid client ID: %v", err)
	}

	pkStore.AddPubKey(clientID, key)

	return c.save()
}

// removePubKey removes the pubkey of the given client id
func (c *client) removePubKey(clientID []byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	pkStore, ok := c.Key.(keys.PubKeyStore)
	if !ok {
		return ErrUnsupportedOperation
	}

	if err := e4crypto.ValidateID(clientID); err != nil {
		return fmt.Errorf("invalid client ID: %v", err)
	}

	err := pkStore.RemovePubKey(clientID)
	if err != nil {
		return err
	}

	return c.save()
}

// resetPubKeys removes all public keys
func (c *client) resetPubKeys() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	pkStore, ok := c.Key.(keys.PubKeyStore)
	if !ok {
		return ErrUnsupportedOperation
	}

	pkStore.ResetPubKeys()

	return c.save()
}

// setIDKey replaces the current ID key with a new one
func (c *client) setIDKey(key []byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.Key.SetKey(key); err != nil {
		return err
	}

	return c.save()
}

// TopicForID generate the receiving topic that a client should subscribe to in order to receive commands
func TopicForID(id []byte) string {
	return idTopicPrefix + hex.EncodeToString(id)
}
