package e4common

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"

	"golang.org/x/crypto/ed25519"

	e4crypto "gitlab.com/teserakt/e4common/crypto"
	"gitlab.com/teserakt/e4common/keys"
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
	ProtectMessage(payload []byte, topic string) ([]byte, error)
	Unprotect(protected []byte, topic string) ([]byte, error)

	setIDKey(key []byte) error

	setPubKey(key, clientID []byte) error
	removePubKey(clientID []byte) error
	resetPubKeys() error
	getPubKeys() (map[string][]byte, error)

	setTopicKey(key, topichash []byte) error
	removeTopic(topichash []byte) error
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
func NewSymKeyClient(id []byte, key []byte, filePath string) (Client, error) {
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

	return newClient(newID, symKeyMaterial, filePath)
}

// NewPubKeyClient creates a new client using a ed25519 private key
func NewPubKeyClient(id []byte, key ed25519.PrivateKey, filePath string, c2PubKey []byte) (Client, error) {
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

	return newClient(newID, pubKeyMaterialKey, filePath)
}

// NewSymKeyClientPretty is like NewClient but takes an client name and a password, rather than raw values
func NewSymKeyClientPretty(name string, password string, filePath string) (Client, error) {
	id := e4crypto.HashIDAlias(name)

	key, err := keys.NewSymKeyMaterialFromPassword(password)
	if err != nil {
		return nil, err
	}

	return newClient(id, key, filePath)
}

// NewPubKeyClientPretty is like NewClient but takes an client name and a password, rather than raw values
func NewPubKeyClientPretty(name string, password string, filePath string, c2PubKey []byte) (Client, error) {
	id := e4crypto.HashIDAlias(name)

	key, err := keys.NewPubKeyMaterialFromPassword(id, password, c2PubKey)
	if err != nil {
		return nil, err
	}

	return newClient(id, key, filePath)
}

// newClient creates a new client, generating a random ID if they are empty
func newClient(id []byte, clientKey keys.KeyMaterial, filePath string) (Client, error) {
	if len(id) == 0 {
		return nil, errors.New("client id must not be empty")
	}

	c := &client{
		Key:            clientKey,
		TopicKeys:      make(map[string]keys.TopicKey),
		FilePath:       filePath,
		ReceivingTopic: topicForID(id),
	}

	c.ID = make([]byte, len(id))
	copy(c.ID, id)

	log.SetPrefix("e4client\t")

	return c, nil
}

// LoadClient loads a client state from the file system
func LoadClient(filePath string) (Client, error) {
	c := &client{}
	err := readJSON(filePath, c)
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
	topichash := hex.EncodeToString(e4crypto.HashTopic(topic))

	c.lock.RLock()
	topicKey, ok := c.TopicKeys[topichash]
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

	topichash := hex.EncodeToString(e4crypto.HashTopic(topic))
	c.lock.RLock()
	key, ok := c.TopicKeys[topichash]
	c.lock.RUnlock()
	if !ok {
		return nil, ErrTopicKeyNotFound
	}

	message, err := c.Key.UnprotectMessage(protected, key)
	if err != nil {
		return nil, err
	}

	return message, nil
}

// setTopicKey adds a key to the given topic hash, erasing any previous entry
func (c *client) setTopicKey(key, topichash []byte) error {
	if err := e4crypto.ValidateTopicHash(topichash); err != nil {
		return fmt.Errorf("invalid topic hash: %v", err)
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	c.TopicKeys[hex.EncodeToString(topichash)] = key
	return c.save()
}

// removeTopic removes the key of the given topic hash
func (c *client) removeTopic(topichash []byte) error {
	if err := e4crypto.ValidateTopicHash(topichash); err != nil {
		return fmt.Errorf("invalid topic hash: %v", err)
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	delete(c.TopicKeys, hex.EncodeToString(topichash))

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
func (c *client) setPubKey(key, clientid []byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	pkStore, ok := c.Key.(keys.PubKeyStore)
	if !ok {
		return ErrUnsupportedOperation
	}

	if err := e4crypto.ValidateID(clientid); err != nil {
		return fmt.Errorf("invalid client ID: %v", err)
	}

	pkStore.AddPubKey(clientid, key)

	return c.save()
}

// removePubKey removes the pubkey of the given client id
func (c *client) removePubKey(clientid []byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	pkStore, ok := c.Key.(keys.PubKeyStore)
	if !ok {
		return ErrUnsupportedOperation
	}

	if err := e4crypto.ValidateID(clientid); err != nil {
		return fmt.Errorf("invalid client ID: %v", err)
	}

	err := pkStore.RemovePubKey(clientid)
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

// topicForID generate the MQTT topic that a client should subscribe to in order to receive commands
func topicForID(id []byte) string {
	return idTopicPrefix + hex.EncodeToString(id)
}
