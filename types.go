package e4common

import (
	"encoding/hex"
	fmt "fmt"
	utf8 "unicode/utf8"
)

// ...
const (
	IDLen           = 16
	KeyLen          = 32
	TagLen          = 16
	HashLen         = 32
	TimestampLen    = 8
	MaxTopicLen     = 512
	MaxSecondsDelay = 60 * 10
	idTopicPrefix   = "e4/"

	IDLenHex  = IDLen * 2
	KeyLenHex = KeyLen * 2

	NameMinLen = 1
	NameMaxLen = 255
)

// Command is a command sent by C2 to a client.
type Command int

// ...
const (
	RemoveTopic Command = iota
	ResetTopics
	SetIDKey
	SetTopicKey
)

// Protocol defines the type of message protection
type Protocol int

// ...
const (
	SymKey Protocol = iota
	PubKey
	PubKeyFIPS
	PostQuantum
)

// ToByte converts a command into its byte representation
func (c *Command) ToByte() byte {
	switch *c {
	case RemoveTopic:
		return 0
	case ResetTopics:
		return 1
	case SetIDKey:
		return 2
	case SetTopicKey:
		return 3
	}
	return 255
}

// ToString converts a command into its string representation.
func (c *Command) ToString() string {

	switch *c {
	case RemoveTopic:
		return "RemoveTopic"
	case ResetTopics:
		return "ResetTopics"
	case SetIDKey:
		return "SetIDKey"
	case SetTopicKey:
		return "SetTopicKey"
	}
	return ""
}

// IsValidName is used to validate names match given constraints
// since we hash these in the protocol, those constraints are quite
// liberal, but for correctness we check any string is valid UTF-8.
func IsValidName(name string) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("Name is not a valid UTF-8 string")
	}
	namelen := len(name)
	if namelen < NameMinLen || namelen > NameMaxLen {
		return fmt.Errorf("Name length is invalid, names are between %d and %d characters", NameMinLen, NameMaxLen)
	}
	return nil
}

// IsValidID checks that an id is of the expected length.
func IsValidID(id []byte) error {

	if len(id) != IDLen {
		return fmt.Errorf("Invalid ID length, expected %d, got %d", IDLen, len(id))
	}

	return nil
}

// IsValidKey checks that a key is of the expected length.
func IsValidKey(key []byte) error {

	if len(key) != KeyLen {
		return fmt.Errorf("Invalid Key length, expected %d, got %d", KeyLen, len(key))
	}

	return nil
}

// IsValidTopic checks if a topic is not too large.
func IsValidTopic(topic string) error {

	if len(topic) > MaxTopicLen {
		return fmt.Errorf("Topic too long, expected %d chars maximum, got %d", MaxTopicLen, len(topic))
	}

	return nil
}

// IsValidTopicHash checks that a topic hash is of the expected length.
func IsValidTopicHash(topichash []byte) error {

	if len(topichash) != HashLen {
		return fmt.Errorf("Invalid Topic Hash length, expected %d, got %d", HashLen, len(topichash))
	}

	return nil
}

// TopicForID generate the MQTT topic that a client should subscribe to in order to receive commands.
func TopicForID(id []byte) string {
	return idTopicPrefix + hex.EncodeToString(id)
}

// PrettyID returns an ID as its first 8 hex chars
func PrettyID(id []byte) string {
	if err := IsValidID(id); err != nil {
		panic(err) // TODO don't panic !  It's a bit brutal to kill the whole program when failed to prettify an ID imo
	}
	return hex.EncodeToString(id)[:8] + ".."
}
