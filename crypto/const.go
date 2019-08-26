package crypto

import "time"

// List of global e4 constants
const (
	IDLen            = 16
	KeyLen           = 32
	TagLen           = 16
	HashLen          = 16
	TimestampLen     = 8
	MaxTopicLen      = 512
	MaxDelayDuration = 10 * time.Minute

	IDLenHex  = IDLen * 2
	KeyLenHex = KeyLen * 2

	NameMinLen = 1
	NameMaxLen = 255
)
