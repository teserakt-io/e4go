package crypto

// ...
const (
	IDLen           = 16
	KeyLen          = 32
	TagLen          = 16
	HashLen         = 16
	TimestampLen    = 8
	MaxTopicLen     = 512
	MaxSecondsDelay = 60 * 10

	IDLenHex  = IDLen * 2
	KeyLenHex = KeyLen * 2

	NameMinLen = 1
	NameMaxLen = 255
)
