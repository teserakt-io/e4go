package crypto

import "golang.org/x/crypto/sha3"

// Sha3Sum256 returns the sha3 sum of given data
func Sha3Sum256(data []byte) []byte {
	h := sha3.Sum256(data)
	return h[:]
}

// HashTopic creates a topic hash from a topic string
func HashTopic(topic string) []byte {
	return Sha3Sum256([]byte(topic))[:HashLen]
}

// HashIDAlias creates an ID from an ID alias string
func HashIDAlias(idalias string) []byte {
	return Sha3Sum256([]byte(idalias))[:IDLen]
}
