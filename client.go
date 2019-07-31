package e4common

import (
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

var (
	// ErrTopicKeyNotFound occurs when a topic key is missing when encryption/decrypting.
	ErrTopicKeyNotFound = errors.New("topic key not found")
	// ErrPubKeyNotFound occurs when a public key is missing when verifying a signature.
	ErrPubKeyNotFound   = errors.New("signer public key not found")
	ErrInvalidProtocol  = errors.New("invalid protocol version")
	ErrInvalidSignature = errors.New("invalid signature")
)

// Client is a structure representing the client state, saved to disk for persistent storage.
type Client struct {
	ID         []byte
	SymKey     []byte             // for SymKey mode only
	Ed25519Key ed25519.PrivateKey // for PubKey mode only
	C2Key      *[32]byte          // C2's key, for  PubKey mode only
	Topickeys  map[string][]byte
	// Topickeys maps a topic hash to a key
	// (slices []byte can't be map keys, converting to strings)
	Pubkeys         map[string][]byte
	FilePath        string
	ReceivingTopic  string
	ProtocolVersion Protocol
}

// NewClient creates a new client, generating a random ID or key if they are nil.
func NewClient(id, symKey []byte, ed25519Key ed25519.PrivateKey, filePath string, protocolVersion Protocol) (*Client, error) {

	var err error

	if id == nil {
		id = RandomID()
	}

	if protocolVersion == SymKey {
		if symKey == nil {
			symKey = RandomKey()
		}
		if err = IsValidSymKey(symKey); err != nil {
			return nil, err
		}
		ed25519Key = nil
	} else if protocolVersion == PubKey {
		if ed25519Key == nil {
			_, ed25519Key, err = ed25519.GenerateKey(nil)
		}
		if err != nil {
			return nil, err
		}
		if err = IsValidPrivKey(ed25519Key); err != nil {
			return nil, err
		}
		symKey = nil
	}

	topickeys := make(map[string][]byte)
	pubkeys := make(map[string][]byte)

	receivingTopic := TopicForID(id)

	c := &Client{
		ID:              id,
		SymKey:          symKey,
		Ed25519Key:      ed25519Key,
		Topickeys:       topickeys,
		Pubkeys:         pubkeys,
		FilePath:        filePath,
		ProtocolVersion: protocolVersion,
		ReceivingTopic:  receivingTopic,
	}

	log.SetPrefix("e4client\t")

	return c, nil
}

// NewClientPretty is like NewClient but takes an ID alias and a password, rather than raw values.
func NewClientPretty(idalias, pwd, filePath string, protocolVersion Protocol) *Client {
	key := HashPwd(pwd)
	id := HashIDAlias(idalias)
	ed25519.SeedSize
	return NewClient(id, key, nil, filePath, protocolVersion)
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

// ProtectMessage ..
func (c *Client) ProtectMessage(payload []byte, topic string) ([]byte, error) {
	topichash := string(HashTopic(topic))
	if key, ok := c.Topickeys[topichash]; ok {

		var protected []byte
		var err error

		switch c.ProtocolVersion {
		case SymKey:
			protected, err = c.protectMessageSymKey(payload, key)
		case PubKey:
			protected, err = c.protectMessagePubKey(payload, key)
		default:
			return nil, ErrInvalidProtocol
		}
		if err != nil {
			return nil, err
		}
		return protected, nil
	}
	return nil, ErrTopicKeyNotFound
}

// Unprotect returns (nil, nil) upon successful protected command, (message, nil) upon sucessful message
func (c *Client) Unprotect(protected []byte, topic string) ([]byte, error) {
	if topic == c.ReceivingTopic {
		return nil, c.unprotectAndProcessCommand(protected)
	}
	return c.unprotectMessage(protected, topic)
}

func (c *Client) unprotectAndProcessCommand(protected []byte) error {

	var command []byte
	var err error

	switch c.ProtocolVersion {

	case SymKey:
		command, err = c.unprotectCommandSymKey(protected)
	case PubKey:
		command, err = c.unprotectCommandPubKey(protected)
	default:
		return ErrInvalidProtocol
	}
	if err != nil {
		return err
	}
	return c.processCommand(command)
}

func (c *Client) unprotectMessage(protected []byte, topic string) ([]byte, error) {
	topichash := string(HashTopic(topic))
	if key, ok := c.Topickeys[topichash]; ok {

		var message []byte
		var err error

		switch c.ProtocolVersion {

		case SymKey:
			message, err = c.unprotectMessageSymKey(protected, key)
		case PubKey:
			message, err = c.unprotectMessagePubKey(protected, key)
		default:
			return nil, ErrInvalidProtocol
		}
		if err != nil {
			return nil, err
		}
		return message, nil
	}
	return nil, ErrTopicKeyNotFound
}

func (c *Client) protectMessageSymKey(message []byte, key []byte) ([]byte, error) {
	return protectSymKey(message, key)
}

func (c *Client) unprotectMessageSymKey(protected []byte, key []byte) ([]byte, error) {
	return c.unprotectSymKey(protected, key)
}

func (c *Client) unprotectCommandSymKey(protected []byte) ([]byte, error) {
	return c.unprotectSymKey(protected, c.SymKey)
}

func (c *Client) unprotectSymKey(protected []byte, key []byte) ([]byte, error) {

	if len(protected) <= TimestampLen {
		return nil, errors.New("ciphertext to short")
	}

	ct := protected[TimestampLen:]
	timestamp := protected[:TimestampLen]

	ts := binary.LittleEndian.Uint64(timestamp)
	now := uint64(time.Now().Unix())
	if now < ts {
		return nil, errors.New("timestamp received is in the future")
	}
	if now-ts > MaxSecondsDelay {
		return nil, errors.New("timestamp too old")
	}

	pt, err := Decrypt(key, timestamp, ct)
	if err != nil {
		return nil, err
	}

	return pt, nil
}

func (c *Client) protectMessagePubKey(message, key []byte) ([]byte, error) {

	timestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().Unix()))

	ct, err := Encrypt(key, timestamp, message)
	if err != nil {
		return nil, err
	}

	protected := append(timestamp, c.ID...)
	protected = append(protected, ct...)

	// sig should always be ed25519.SignatureSize=64 bytes
	sig := ed25519.Sign(c.Ed25519Key, protected)

	protected = append(protected, sig...)

	return protected, nil
}

func (c *Client) unprotectCommandPubKey(protected []byte) ([]byte, error) {

	// convert ed key to curve key
	var curvekey *[32]byte
	var edkey [64]byte
	copy(edkey[:], c.Ed25519Key)
	extra25519.PrivateKeyToCurve25519(curvekey, &edkey)

	var shared *[32]byte
	curve25519.ScalarMult(shared, curvekey, c.C2Key)

	key := hashStuff(shared[:])[:KeyLen]

	return c.unprotectSymKey(protected, key)
}

func (c *Client) unprotectMessagePubKey(protected []byte, key []byte) ([]byte, error) {

	if len(protected) <= TimestampLen+ed25519.SignatureSize {
		return nil, errors.New("ciphertext to short")
	}

	// first check timestamp
	timestamp := protected[:TimestampLen]

	ts := binary.LittleEndian.Uint64(timestamp)
	now := uint64(time.Now().Unix())
	if now < ts {
		return nil, errors.New("timestamp received is in the future")
	}
	if now-ts > MaxSecondsDelay {
		return nil, errors.New("timestamp too old")
	}

	// then check signature
	signerID := string(protected[TimestampLen : TimestampLen+IDLen])
	signed := protected[:len(protected)-ed25519.SignatureSize]
	sig := protected[len(protected)-ed25519.SignatureSize:]

	if pubkey, ok := c.Pubkeys[signerID]; ok {
		if !ed25519.Verify(ed25519.PublicKey(pubkey), signed, sig) {
			return nil, ErrInvalidSignature
		}
	} else {
		return nil, ErrPubKeyNotFound
	}

	ct := protected[TimestampLen+IDLen : len(protected)-ed25519.SignatureSize]

	// finally decrypt
	pt, err := Decrypt(key, timestamp, ct)
	if err != nil {
		return nil, err
	}

	return pt, nil
}

func (c *Client) processCommand(command []byte) error {

	switch Command(command[0]) {

	case RemoveTopic:
		if len(command) != HashLen+1 {
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
		if len(command) != KeyLen+1 {
			return errors.New("invalid SetIDKey length")
		}
		return c.SetIDKey(command[1:])

	case SetTopicKey:
		if len(command) != KeyLen+HashLen+1 {
			return errors.New("invalid SetTopicKey length")
		}
		log.Println("setting topic key for hash ", hex.EncodeToString(command[1+KeyLen:]))
		return c.SetTopicKey(command[1:1+KeyLen], command[1+KeyLen:])

	case RemovePubKey:
		if len(command) != IDLen+1 {
			return errors.New("invalid RemovePubKey length")
		}
		log.Println("remove pubkey for client ", hex.EncodeToString(command[1:]))
		return c.RemoveTopic(command[1:])

	case ResetPubKeys:
		if len(command) != 1 {
			return errors.New("invalid ResetPubKeys length")
		}
		return c.ResetTopics()

	case SetPubKey:
		if len(command) != ed25519.PublicKeySize+IDLen+1 {
			return errors.New("invalid SetPubKey length")
		}
		log.Println("setting pubkey for client ", hex.EncodeToString(command[1+ed25519.PublicKeySize:]))
		return c.SetPubKey(command[1:1+ed25519.PublicKeySize], command[1+ed25519.PublicKeySize:])

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

// RemovePubKey removes the pubkey of the given client id
func (c *Client) RemovePubKey(clientid []byte) error {
	if err := IsValidID(clientid); err != nil {
		return fmt.Errorf("invalid client ID: %v", err)
	}
	delete(c.Pubkeys, string(clientid))

	return c.save()
}

// ResetTopics removes all topic keys
func (c *Client) ResetTopics() error {
	c.Topickeys = make(map[string][]byte)
	return c.save()
}

// ResetPubKeys removes all public keys
func (c *Client) ResetPubKeys() error {
	c.Pubkeys = make(map[string][]byte)
	return c.save()
}

// SetIDKey replaces the current ID key with a new one
func (c *Client) SetIDKey(key []byte) error {
	if c.ProtocolVersion == SymKey {
		c.SymKey = key
	} else if c.ProtocolVersion == PubKey {
		c.Ed25519Key = key
	}
	return c.save()
}

// SetTopicKey adds a key to the given topic hash, erasing any previous entry
func (c *Client) SetTopicKey(key, topichash []byte) error {
	c.Topickeys[string(topichash)] = key
	return c.save()
}

// SetPubKey adds a key to the given topic hash, erasing any previous entry
func (c *Client) SetPubKey(key, clientid []byte) error {
	c.Pubkeys[string(clientid)] = key
	return c.save()
}
