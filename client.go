//
// Package e4go provides a e4 client implementation and libraries.
//
// It aims to be quick and easy to integrate in IoT devices applications
// enabling to secure their communications, as well as exposing a way to manage the various keys required.
//
// Creating a client
//
// the package provides several helpers to instantiate a client using symmetric keys:
//  client, err := NewSymKeyClient([]byte("clientID"), crypto.RandomKey(), "./symClient.json")
//  client, err := NewSymKeyClientPretty("clientName", "secretPassword", "./symClient.json")
// or asymmetric keys:
//  client, err := NewPubKeyClient([]byte("clientID"), privateKey, "./asymClient.json", sharedPubKey)
//  client, err := NewPubKeyClientPretty([]byte("clientID"), "secretPassword", "./asymClient.json", sharedPubKey)
// see provided examples for a more detailed usage.
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
package e4go

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	miscreant "github.com/miscreant/miscreant.go"
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
	setPubKey(key, clientID []byte) error
	// removePubKey remove the public key for the given clientID, if the client key material support it.
	// otherwise, ErrUnsupportedOperation is returned
	removePubKey(clientID []byte) error
	// resetPubKeys remove all pubKeys from the key material, if it support it.
	// otherwise, ErrUnsupportedOperation is returned
	resetPubKeys() error
	// getPubKeys returns the map of public keys having been set on the client, if the client key material support it.
	// otherwise, ErrUnsupportedOperation is returned
	getPubKeys() (map[string][]byte, error)
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

	FilePath       string
	ReceivingTopic string

	lock sync.RWMutex
}

var _ Client = (*client)(nil)

// NewSymKeyClient creates a new client using a symmetric key
//
// id is a client identifier, and must be of length e4crypto.IDLen bytes.
// key is the client private key,  and must be of length  e4crypto.KeyLen bytes.
// persistStatePath is the file system path to the file to read and persist the client's state.
func NewSymKeyClient(id []byte, key []byte, persistStatePath string) (Client, error) {
	var newID []byte
	if len(id) == 0 {
		newID = e4crypto.RandomID()
	} else {
		newID = make([]byte, len(id))
		copy(newID, id)
	}

	symKeyMaterial, err := keys.NewSymKeyMaterial(key)
	if err != nil {
		return nil, fmt.Errorf("failed to created symkey from key: %v", err)
	}

	return newClient(newID, symKeyMaterial, persistStatePath)
}

// NewPubKeyClient creates a new client using the provided ed25519 private key.
//
// id is a client identifier, and must be of length e4crypto.IDLen bytes.
// key is the ed25519 private key.
// persistStatePath is the file system path to the file to read and persist the client's state.
// c2PubKey must be the curve25519 public part of the key that was used to protect client commands.
func NewPubKeyClient(id []byte, key ed25519.PrivateKey, persistStatePath string, c2PubKey []byte) (Client, error) {
	var newID []byte
	if len(id) == 0 {
		newID = e4crypto.RandomID()
	} else {
		newID = make([]byte, len(id))
		copy(newID, id)
	}

	pubKeyMaterialKey, err := keys.NewPubKeyMaterial(newID, key, c2PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create ed25519key from key: %v", err)
	}

	return newClient(newID, pubKeyMaterialKey, persistStatePath)
}

// NewSymKeyClientPretty is like NewClient but takes a client name and a password
//
// name is the unique identifier for the client.
// password will be used to derive the client key. It must be at least 16 characters long.
// persistStatePath is the file system path to the file to read and persist the client's state.
func NewSymKeyClientPretty(name string, password string, persistStatePath string) (Client, error) {
	id := e4crypto.HashIDAlias(name)

	key, err := keys.NewSymKeyMaterialFromPassword(password)
	if err != nil {
		return nil, err
	}

	return newClient(id, key, persistStatePath)
}

// NewPubKeyClientPretty is like NewPubKeyClient except that it takes in the client's name and a password.
//
// name is the unique identifier for the client.
// password will be used to derive the client key. It must be at least 16 characters long.
// persistStatePath is a file system path to the file to be used to read
// and persist the client's current state.
// c2PubKey must be the curve25519 public part of the key that was used to protect client commands.
func NewPubKeyClientPretty(name string, password string, persistStatePath string, c2PubKey []byte) (Client, ed25519.PublicKey, error) {
	id := e4crypto.HashIDAlias(name)

	key, err := keys.NewPubKeyMaterialFromPassword(id, password, c2PubKey)
	if err != nil {
		return nil, nil, err
	}

	client, err := newClient(id, key, persistStatePath)
	if err != nil {
		return nil, nil, err
	}

	return client, key.PublicKey(), nil
}

// newClient creates a new client, generating a random ID if they are empty
func newClient(id []byte, clientKey keys.KeyMaterial, persistStatePath string) (Client, error) {
	if len(id) == 0 {
		return nil, errors.New("client id must not be empty")
	}

	c := &client{
		Key:            clientKey,
		TopicKeys:      make(map[string]keys.TopicKey),
		FilePath:       persistStatePath,
		ReceivingTopic: TopicForID(id),
	}

	c.ID = make([]byte, len(id))
	copy(c.ID, id)

	log.SetPrefix("e4client\t")

	return c, nil
}

// LoadClient loads a client state from the file system
func LoadClient(persistStatePath string) (Client, error) {
	c := &client{}
	err := readJSON(persistStatePath, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *client) save() error {
	err := writeJSON(c.FilePath, c)
	if err != nil {
		log.Printf("failed to save client: %v", err)
		return err
	}
	return nil
}

func writeJSON(filePath string, object interface{}) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file at %s: %v", filePath, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(object)

	return err
}

func readJSON(filePath string, object interface{}) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(object)
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

	if rawFilePath, ok := m["FilePath"]; ok {
		if err := json.Unmarshal(rawFilePath, &c.FilePath); err != nil {
			return fmt.Errorf("failed to unmarshal client filepath: %v", err)
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

	// If decryption failed, try previous key if exists and not too old
	if err == miscreant.ErrNotAuthentic {
		hashHash := hex.EncodeToString(e4crypto.HashTopic(string(topicHash)))
		topicKeyTs, ok := c.TopicKeys[hashHash]
		if ok {
			if len(topicKeyTs) != e4crypto.KeyLen+e4crypto.TimestampLen {
				return nil, errors.New("invalid old topic key length")
			}
			topicKey := make([]byte, e4crypto.KeyLen)
			copy(topicKey, topicKeyTs[:e4crypto.KeyLen])
			timestamp := topicKeyTs[e4crypto.KeyLen:]

			err := e4crypto.ValidateTimestampKey(timestamp)
			if err != nil {
				return nil, err
			}

			message, err = c.Key.UnprotectMessage(protected, topicKey)
			if err == nil {
				return message, nil
			}
		}
	}

	if err != nil {
		return nil, err
	}

	return message, nil
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
			hashHash := e4crypto.HashTopic(string(topicHash))
			timestamp := make([]byte, e4crypto.TimestampLen)
			binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().Unix()))
			topicKey = append(topicKey, timestamp...)
			c.TopicKeys[hex.EncodeToString(hashHash)] = topicKey
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
	hashHash := e4crypto.HashTopic(string(topicHash))
	delete(c.TopicKeys, hex.EncodeToString(hashHash))

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
func (c *client) getPubKeys() (map[string][]byte, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	pkStore, ok := c.Key.(keys.PubKeyStore)
	if !ok {
		return nil, ErrUnsupportedOperation
	}

	return pkStore.GetPubKeys(), nil
}

// setPubKey adds a key to the given topic hash, erasing any previous entry
func (c *client) setPubKey(key, clientID []byte) error {
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
