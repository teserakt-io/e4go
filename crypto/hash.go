package crypto

import "golang.org/x/crypto/sha3"

// HashStuff returns the sha3 sum of given data
// TODO rename to more appropriate name
func HashStuff(data []byte) []byte {
	h := sha3.Sum256(data)
	return h[:]
}

// HashTopic creates a topic hash from a topic string.
func HashTopic(topic string) []byte {
	return HashStuff([]byte(topic))[:HashLen]
}

// HashIDAlias creates an ID from an ID alias string.
func HashIDAlias(idalias string) []byte {
	return HashStuff([]byte(idalias))[:IDLen]
}
