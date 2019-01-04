package e4common

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"github.com/miscreant/miscreant-go"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// HashTopic creates a topic hash from a topic string.
func HashTopic(topic string) []byte {

	return hashStuff([]byte(topic))
}

// HashIDAlias creates an ID from an ID alias string.
func HashIDAlias(idalias string) []byte {

	return hashStuff([]byte(idalias))
}

// HashPwd hashes a password with Argon2
func HashPwd(pwd string) []byte {

	return argon2.Key([]byte(pwd), nil, 1, 64*1024, 4, 64)
}

func hashStuff(data []byte) []byte {
	h := sha3.Sum256(data)
	return h[:]
}

// Encrypt creates an authenticated ciphertext.
func Encrypt(key []byte, ad []byte, pt []byte) ([]byte, error) {

	c, err := miscreant.NewAESCMACSIV(key)
	if err != nil {
		return []byte{}, err
	}
	ads := make([][]byte, 1)
	ads[0] = ad
	return c.Seal(nil, pt, ads...)
}

// Decrypt decrypts and verifies an authenticated ciphertext.
func Decrypt(key []byte, ad []byte, ct []byte) ([]byte, error) {

	c, err := miscreant.NewAESCMACSIV(key)
	if err != nil {
		return []byte{}, err
	}
	if len(ct) < c.Overhead() {
		return []byte{}, errors.New("too short ciphertext")
	}
	ads := make([][]byte, 1)
	ads[0] = ad
	return c.Open(nil, ct, ads...)
}

// RandomKey generates a random 64-byte key usable by Encrypt and Decrypt.
func RandomKey() []byte {
	key := make([]byte, KeyLen)
	rand.Read(key)
	return key
}

// RandomID generates a random 32-byte ID.
func RandomID() []byte {
	id := make([]byte, IDLen)
	rand.Read(id)
	return id
}

// Protect creates a protected messages, generating a timestamp and a ciphertext.
func Protect(message []byte, key []byte) ([]byte, error) {

	timestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().Unix()))

	ct, err := Encrypt(key, timestamp, message)
	if err != nil {
		return nil, err
	}
	protected := append(timestamp, ct...)

	return protected, nil
}

// Unprotect verifies a protected message's timestamp and ciphertext and decrypts it.
func Unprotect(protected []byte, key []byte) ([]byte, error) {

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
