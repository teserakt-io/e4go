package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/ed25519"
)

var (
	blankEd25519pk [ed25519.PublicKeySize]byte
	zeroEd25519pk  = blankEd25519pk[:]
	blankEd25519sk [ed25519.PrivateKeySize]byte
	zeroEd25519sk  = blankEd25519sk[:]

	blankSymKey [KeyLen]byte
	zeroSymKey  = blankSymKey[:]
)

// ValidateSymKey checks that a key is of the expected length.
func ValidateSymKey(key []byte) error {
	if len(key) != KeyLen {
		return fmt.Errorf("Invalid symmetric key length, expected %d, got %d", KeyLen, len(key))
	}

	// TODO: validate this check
	if bytes.Equal(zeroSymKey, key) {
		return errors.New("Invalid symmetric key, all zeros")
	}

	return nil
}

// ValidEd25519PrivKey checks that a key is of the expected length and not all zero.
func ValidEd25519PrivKey(key []byte) error {
	if g, w := len(key), ed25519.PrivateKeySize; g != w {
		return fmt.Errorf("Invalid private key length, expected %d, got %d", g, w)
	}

	if bytes.Equal(zeroEd25519sk, key) {
		return errors.New("Invalid private key, all zeros")
	}

	return nil
}

// ValidateEd25519PubKey checks that a key is of the expected length and not all zero.
func ValidateEd25519PubKey(key []byte) error {
	if g, w := len(key), ed25519.PublicKeySize; g != w {
		return fmt.Errorf("Invalid public key length, expected %d, got %d", g, w)
	}

	if bytes.Equal(zeroEd25519pk, key) {
		return errors.New("Invalid public key, all zeros")
	}

	return nil
}

// ValidateID checks that an id is of the expected length.
func ValidateID(id []byte) error {
	if len(id) != IDLen {
		return fmt.Errorf("Invalid ID length, expected %d, got %d", IDLen, len(id))
	}

	return nil
}

// ValidateName is used to validate names match given constraints
// since we hash these in the protocol, those constraints are quite
// liberal, but for correctness we check any string is valid UTF-8.
func ValidateName(name string) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("Name is not a valid UTF-8 string")
	}

	namelen := len(name)
	if namelen < NameMinLen || namelen > NameMaxLen {
		return fmt.Errorf("Name length is invalid, names are between %d and %d characters", NameMinLen, NameMaxLen)
	}

	return nil
}

// ValidateTopic checks if a topic is not too large.
func ValidateTopic(topic string) error {
	if len(topic) > MaxTopicLen {
		return fmt.Errorf("Topic too long, expected %d chars maximum, got %d", MaxTopicLen, len(topic))
	}

	return nil
}

// ValidateTopicHash checks that a topic hash is of the expected length.
func ValidateTopicHash(topichash []byte) error {
	if len(topichash) != HashLen {
		return fmt.Errorf("Invalid Topic Hash length, expected %d, got %d", HashLen, len(topichash))
	}

	return nil
}
