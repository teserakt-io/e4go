package e4common

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ed25519"

	e4crypto "gitlab.com/teserakt/e4common/crypto"
	"gitlab.com/teserakt/e4common/keys"
)

const (
	idTopicPrefix = "e4/"
)

var (
	// ErrTopicKeyNotFound occurs when a topic key is missing when encryption/decrypting.
	ErrTopicKeyNotFound = errors.New("topic key not found")
	// ErrUnsupportedOperation occurs when trying to manipulate client public keys with a ClientKey not supporting it
	ErrUnsupportedOperation = errors.New("this operation is not supported")
)

// Client defines interface for protecting and unprotecting E4 messages and commands.
type Client interface {
	ProtectMessage(payload []byte, topic string) ([]byte, error)
	Unprotect(protected []byte, topic string) ([]byte, error)
	RemoveTopic(topichash []byte) error
	ResetTopics() error
	SetPubKey(key, clientID []byte) error
	RemovePubKey(clientID []byte) error
	ResetPubKeys() error
	SetIDKey(key []byte) error
	SetTopicKey(key, topichash []byte) error
}

// client implements Client interface.
// It holds the client state and is saved to disk for persistent storage.
type client struct {
	ID []byte
	// TopicKeys maps a topic hash to a key
	// (slices []byte can't be map keys, converting to strings)
	TopicKeys map[string]keys.TopicKey

	Key keys.ClientKey

	FilePath       string
	ReceivingTopic string
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

	symKey, err := keys.NewSymKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to created symkey from key: %v", err)
	}

	return newClient(newID, symKey, filePath)
}

// NewPubKeyClient creates a new client using a ed25519 private key
func NewPubKeyClient(id []byte, key ed25519.PrivateKey, filePath string, c2PublicKey [32]byte) (Client, error) {
	var newID []byte
	if len(id) == 0 {
		newID = e4crypto.RandomID()
	} else {
		newID = make([]byte, len(id))
		copy(newID, id)
	}

	ed25519Key, err := keys.NewEd25519Key(newID, key, c2PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create ed25519key from key: %v", err)
	}

	return newClient(newID, ed25519Key, filePath)
}

// newClient creates a new client, generating a random ID if they are empty.
func newClient(id []byte, clientKey keys.ClientKey, filePath string) (Client, error) {
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

// NewClientPretty is like NewClient but takes an client name and a password, rather than raw values.
func NewClientPretty(name string, key keys.ClientKey, filePath string) (Client, error) {
	id := e4crypto.HashIDAlias(name)
	return newClient(id, key, filePath)
}

// LoadClient loads a client state from the file system.
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
		log.Print("client save failed")
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

// ProtectMessage ..
func (c *client) ProtectMessage(payload []byte, topic string) ([]byte, error) {
	topichash := string(e4crypto.HashTopic(topic))
	topicKey, ok := c.TopicKeys[topichash]
	if !ok {
		return nil, ErrTopicKeyNotFound
	}

	protected, err := c.Key.ProtectMessage(payload, topicKey)
	if err != nil {
		return nil, err
	}

	return protected, nil
}

// Unprotect returns (nil, nil) upon successful protected command, (message, nil) upon sucessful message
func (c *client) Unprotect(protected []byte, topic string) ([]byte, error) {
	if topic == c.ReceivingTopic {
		command, err := c.Key.UnprotectCommand(protected)
		if err != nil {
			return nil, err
		}

		err = c.processCommand(command)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}

	topichash := string(e4crypto.HashTopic(topic))
	key, ok := c.TopicKeys[topichash]
	if !ok {
		return nil, ErrTopicKeyNotFound
	}

	message, err := c.Key.UnprotectMessage(protected, key)
	if err != nil {
		return nil, err
	}

	return message, nil
}

func (c *client) processCommand(command []byte) error {
	switch Command(command[0]) {

	case RemoveTopic:
		if len(command) != e4crypto.HashLen+1 {
			return errors.New("invalid RemoveTopic length")
		}
		log.Println("remove topic ", hex.EncodeToString(command[1:]))
		return c.RemoveTopic(command[1:])

	case ResetTopics:
		if len(command) != 1 {
			return errors.New("invalid ResetTopics length")
		}
		return c.ResetTopics()

	case SetIDKey:
		if len(command) != e4crypto.KeyLen+1 {
			return errors.New("invalid SetIDKey length")
		}
		return c.SetIDKey(command[1:])

	case SetTopicKey:
		if len(command) != e4crypto.KeyLen+e4crypto.HashLen+1 {
			return errors.New("invalid SetTopicKey length")
		}
		log.Println("setting topic key for hash ", hex.EncodeToString(command[1+e4crypto.KeyLen:]))
		return c.SetTopicKey(command[1:1+e4crypto.KeyLen], command[1+e4crypto.KeyLen:])

	case RemovePubKey:
		if len(command) != e4crypto.IDLen+1 {
			return errors.New("invalid RemovePubKey length")
		}
		log.Println("remove pubkey for client ", hex.EncodeToString(command[1:]))
		return c.RemovePubKey(command[1:])

	case ResetPubKeys:
		if len(command) != 1 {
			return errors.New("invalid ResetPubKeys length")
		}
		return c.ResetPubKeys()

	case SetPubKey:
		if len(command) != ed25519.PublicKeySize+e4crypto.IDLen+1 {
			return errors.New("invalid SetPubKey length")
		}
		log.Println("setting pubkey for client ", hex.EncodeToString(command[1+ed25519.PublicKeySize:]))
		return c.SetPubKey(command[1:1+ed25519.PublicKeySize], command[1+ed25519.PublicKeySize:])

	default:
		return errors.New("invalid command")
	}
}

// RemoveTopic removes the key of the given topic hash
func (c *client) RemoveTopic(topichash []byte) error {
	if err := e4crypto.ValidateTopicHash(topichash); err != nil {
		return fmt.Errorf("invalid topic hash: %v", err)
	}
	delete(c.TopicKeys, string(topichash))

	return c.save()
}

// ResetTopics removes all topic keys
func (c *client) ResetTopics() error {
	c.TopicKeys = make(map[string]keys.TopicKey)
	return c.save()
}

// SetPubKey adds a key to the given topic hash, erasing any previous entry
func (c *client) SetPubKey(key, clientid []byte) error {
	pkStore, ok := c.Key.(keys.PubKeyStore)
	if !ok {
		return ErrUnsupportedOperation
	}

	if err := e4crypto.ValidateID(clientid); err != nil {
		return fmt.Errorf("invalid client ID: %v", err)
	}

	pkStore.AddPubKey(string(clientid), key)

	return c.save()
}

// RemovePubKey removes the pubkey of the given client id
func (c *client) RemovePubKey(clientid []byte) error {
	pkStore, ok := c.Key.(keys.PubKeyStore)
	if !ok {
		return ErrUnsupportedOperation
	}

	if err := e4crypto.ValidateID(clientid); err != nil {
		return fmt.Errorf("invalid client ID: %v", err)
	}

	err := pkStore.RemovePubKey(string(clientid))
	if err != nil {
		return err
	}

	return c.save()
}

// ResetPubKeys removes all public keys
func (c *client) ResetPubKeys() error {
	pkStore, ok := c.Key.(keys.PubKeyStore)
	if !ok {
		return ErrUnsupportedOperation
	}

	pkStore.ResetPubKeys()

	return c.save()
}

// SetIDKey replaces the current ID key with a new one
func (c *client) SetIDKey(key []byte) error {
	if err := c.Key.SetKey(key); err != nil {
		return err
	}

	return c.save()
}

// SetTopicKey adds a key to the given topic hash, erasing any previous entry
func (c *client) SetTopicKey(key, topichash []byte) error {
	c.TopicKeys[string(topichash)] = key
	return c.save()
}

// topicForID generate the MQTT topic that a client should subscribe to in order to receive commands.
func topicForID(id []byte) string {
	return idTopicPrefix + hex.EncodeToString(id)
}
