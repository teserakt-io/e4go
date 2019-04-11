package e4common

import (
	"encoding/hex"
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

// IsValidID checks that an id is of the expected length.
func IsValidID(id []byte) bool {

	if len(id) != IDLen {
		return false
	}
	return true
}

// IsValidKey checks that a key is of the expected length.
func IsValidKey(key []byte) bool {

	if len(key) != KeyLen {
		return false
	}
	return true
}

// IsValidTopic checks if a topic is not too large.
func IsValidTopic(topic string) bool {

	if len(topic) > MaxTopicLen {
		return false
	}
	return true
}

// IsValidTopicHash checks that a topic hash is of the expected length.
func IsValidTopicHash(topichash []byte) bool {

	if len(topichash) != HashLen {
		return false
	}
	return true
}

// TopicForID generate the MQTT topic that a client should subscribe to in order to receive commands.
func TopicForID(id []byte) string {
	return idTopicPrefix + hex.EncodeToString(id)
}

// PrettyID returns an ID as its first 8 hex chars
func PrettyID(id []byte) string {
	if !IsValidID(id) {
		panic("invalid ID")
	}
	return hex.EncodeToString(id)[:8] + ".."
}
