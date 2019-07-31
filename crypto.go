package e4common

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	miscreant "github.com/miscreant/miscreant/go"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

// HashTopic creates a topic hash from a topic string.
func HashTopic(topic string) []byte {

	return hashStuff([]byte(topic))[:HashLen]
}

// HashIDAlias creates an ID from an ID alias string.
func HashIDAlias(idalias string) []byte {

	return hashStuff([]byte(idalias))[:IDLen]
}

// DeriveSymKey derives a symmetric key from a password using Argon2.
// (Replaces HashPwd)
func DeriveSymKey(pwd string) []byte {

	return argon2.Key([]byte(pwd), nil, 1, 64*1024, 4, KeyLen)
}

// DerivePrivKey derives an Ed25519 private key from a password using Argon2.
// (Replaces HashPwd)
func DerivePrivKey(pwd string) ed25519.PrivateKey {

	seed := argon2.Key([]byte(pwd), nil, 1, 64*1024, 4, ed25519.SeedSize)
	return ed25519.NewKeyFromSeed(seed)
}

func hashStuff(data []byte) []byte {
	h := sha3.Sum256(data)
	return h[:]
}

// Encrypt creates an authenticated ciphertext.
func Encrypt(key []byte, ad []byte, pt []byte) ([]byte, error) {

	if err := IsValidSymKey(key); err != nil {
		return nil, err
	}

	// Use same key for CMAC and CTR, negligible security bound difference
	doublekey := append(key, key...)

	c, err := miscreant.NewAESCMACSIV(doublekey)
	if err != nil {
		return nil, err
	}
	ads := make([][]byte, 1)
	ads[0] = ad
	return c.Seal(nil, pt, ads...)
}

// Decrypt decrypts and verifies an authenticated ciphertext.
func Decrypt(key []byte, ad []byte, ct []byte) ([]byte, error) {

	if err := IsValidSymKey(key); err != nil {
		return nil, err
	}

	// Use same key for CMAC and CTR, negligible security bound difference
	doublekey := append(key, key...)

	c, err := miscreant.NewAESCMACSIV(doublekey)
	if err != nil {
		return nil, err
	}
	if len(ct) < c.Overhead() {
		return nil, errors.New("too short ciphertext")
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

// ProtectCommandSymKey is called by C2, not clients
func ProtectCommandSymKey(command []byte, key []byte) ([]byte, error) {

	return protectSymKey(command, key)
}

// ProtectCommandPubKey is called by C2, not clients
func ProtectCommandPubKey(command []byte, clientpk, c2sk *[32]byte) ([]byte, error) {

	var shared *[32]byte
	curve25519.ScalarMult(shared, c2sk, clientpk)

	key := hashStuff(shared[:])[:KeyLen]

	return protectSymKey(command, key)
}

func protectSymKey(payload []byte, key []byte) ([]byte, error) {

	timestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().Unix()))

	ct, err := Encrypt(key, timestamp, payload)
	if err != nil {
		return nil, err
	}
	protected := append(timestamp, ct...)

	return protected, nil
}
