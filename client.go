package e4common

import (
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
)

// ErrTopicKeyNotFound will signal to applications that a key is missing.
var (
	ErrTopicKeyNotFound = errors.New("topic key not found")
)

// Client is a structure representing the client state, saved to disk for persistent storage.
type Client struct {
	ID        []byte
	Key       []byte
	Topickeys map[string][]byte
	// Topickeys maps a topic hash to a key
	// (slices []byte can't be map keys, converting to strings)
	FilePath       string
	ReceivingTopic string
}

// NewClient creates a new client, generating a random ID or key if they are nil.
func NewClient(id, key []byte, filePath string) *Client {
	if id == nil {
		id = RandomID()
	}
	if key == nil {
		key = RandomKey()
	}
	topickeys := make(map[string][]byte)

	receivingTopic := TopicForID(id)

	c := &Client{
		ID:             id,
		Key:            key,
		Topickeys:      topickeys,
		FilePath:       filePath,
		ReceivingTopic: receivingTopic,
	}

	log.SetPrefix("e4client\t")

	return c
}

// NewClientPretty is like NewClient but takes an ID alias and a password, rather than raw values.
func NewClientPretty(idalias, pwd, filePath string) *Client {
	key := HashPwd(pwd)
	id := HashIDAlias(idalias)
	return NewClient(id, key, filePath)
}

// LoadClient loads a client state from the file system.
func LoadClient(filePath string) (*Client, error) {
	var c = new(Client)
	err := readGob(filePath, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) save() error {
	err := writeGob(c.FilePath, c)
	if err != nil {
		log.Print("client save failed")
		return err
	}
	return nil
}

func writeGob(filePath string, object interface{}) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	encoder := gob.NewEncoder(file)
	err = encoder.Encode(object)
	file.Close()
	return err
}

func readGob(filePath string, object interface{}) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(object)
	file.Close()
	return err
}

// Protect creates the protected payload using the key associated to the topic.
func (c *Client) Protect(payload []byte, topic string) ([]byte, error) {
	topichash := string(HashTopic(topic))
	if key, ok := c.Topickeys[topichash]; ok {

		protected, err := Protect(payload, key)
		if err != nil {
			return nil, err
		}
		return protected, nil
	}
	return nil, ErrTopicKeyNotFound
}

// Unprotect decrypts a protected payload using the key associated to the topic.
func (c *Client) Unprotect(protected []byte, topic string) ([]byte, error) {
	if topic == c.ReceivingTopic {
		return nil, c.unprotectAndProcessCommand(protected)
	}
	return c.unprotectMessage(protected, topic)
}

func (c *Client) unprotectAndProcessCommand(protected []byte) error {

	command, err := Unprotect(protected, c.Key)
	if err != nil {
		return err
	}
	return c.processCommand(command)
}

func (c *Client) unprotectMessage(protected []byte, topic string) ([]byte, error) {

	topichash := string(HashTopic(topic))
	if key, ok := c.Topickeys[topichash]; ok {

		message, err := Unprotect(protected, key)
		if err != nil {
			return nil, err
		}
		return message, nil
	}
	return nil, ErrTopicKeyNotFound
}

// ProcessCommand decrypts a C2 commands and modifies the client state according to the command content.
func (c *Client) processCommand(command []byte) error {

	cmd := Command(command[0])

	switch cmd {

	case RemoveTopic:
		if len(command) != HashLen+1 {
			return errors.New("invalid RemoveTopic argument")
		}
		log.Println("remove topic ", hex.EncodeToString(command[1:]))
		return c.RemoveTopic(command[1:])

	case ResetTopics:
		if len(command) != 1 {
			return errors.New("invalid ResetTopics argument")
		}
		return c.ResetTopics()

	case SetIDKey:
		if len(command) != KeyLen+1 {
			return errors.New("invalid SetIDKey argument")
		}
		return c.SetIDKey(command[1:])

	case SetTopicKey:
		if len(command) != KeyLen+HashLen+1 {
			return errors.New("invalid SetTopicKey argument")
		}
		log.Println("setting topic key for hash ", hex.EncodeToString(command[1+KeyLen:]))
		return c.SetTopicKey(command[1:1+KeyLen], command[1+KeyLen:])

	default:
		return errors.New("invalid command")
	}
}

// RemoveTopic removes the key of the given topic hash
func (c *Client) RemoveTopic(topichash []byte) error {
	if err := IsValidTopicHash(topichash); err != nil {
		return fmt.Errorf("invalid topic hash: %v", err)
	}
	delete(c.Topickeys, string(topichash))

	return c.save()
}

// ResetTopics removes all topic keys
func (c *Client) ResetTopics() error {
	c.Topickeys = make(map[string][]byte)
	return c.save()
}

// SetIDKey replaces the current ID key with a new one
func (c *Client) SetIDKey(key []byte) error {
	c.Key = key
	return c.save()
}

// SetTopicKey adds a key to the given topic hash, erasing any previous entry
func (c *Client) SetTopicKey(key, topichash []byte) error {
	c.Topickeys[string(topichash)] = key
	return c.save()
}
