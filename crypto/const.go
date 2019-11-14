package crypto

import "time"

// List of global e4 constants
const (
	// IDLen is the length of an E4 ID
	IDLen = 16
	// KeyLen is the length of a symmetric key
	KeyLen = 32
	// TagLen is the length of the authentication tag appended to the cipher
	TagLen = 16
	// HashLen is the length of a hashed topic
	HashLen = 16
	// TimestampLen is the length of the timestamp
	TimestampLen = 8
	// MaxTopicLen is the maximum length of a topic
	MaxTopicLen = 512
	// MaxDelayDuration is the validity time of a protected message
	MaxDelayDuration = 10 * time.Minute
	// MaxDelayKeyTransition is the validity time of an old topic key once updated
	MaxDelayKeyTransition = 60 * time.Minute
	// IDLenHex is the length of a hexadecimal encoded ID
	IDLenHex = IDLen * 2
	// KeyLenHex is the length of a hexadecimal encoded key
	KeyLenHex = KeyLen * 2
)
