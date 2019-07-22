package e4common

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	miscreant "github.com/miscreant/miscreant/go"
	"golang.org/x/crypto/argon2"
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

// HashPwd hashes a password with Argon2
func HashPwd(pwd string) []byte {

	return argon2.Key([]byte(pwd), nil, 1, 64*1024, 4, KeyLen)
}

func hashStuff(data []byte) []byte {
	h := sha3.Sum256(data)
	return h[:]
}

// Encrypt creates an authenticated ciphertext.
func Encrypt(key []byte, ad []byte, pt []byte) ([]byte, error) {

	if err := IsValidKey(key); err != nil {
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

	if err := IsValidKey(key); err != nil {
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

// ProtectSymKey creates a protected message in the symmetric key mode
func ProtectSymKey(message []byte, key []byte) ([]byte, error) {

	timestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().Unix()))

	ct, err := Encrypt(key, timestamp, message)
	if err != nil {
		return nil, err
	}
	protected := append(timestamp, ct...)

	return protected, nil
}

// UnprotectSymKey verifies a protected message's in the symmetric key mode, returning the plaintext if it succeeds
func UnprotectSymKey(protected []byte, key []byte) ([]byte, error) {

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

// ProtectPubKey protects a non-command message using pubkey crypto
func ProtectPubKey(message, key []byte, edkey ed25519.PrivateKey, clientID []byte) ([]byte, error) {

	timestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().Unix()))

	ct, err := Encrypt(key, timestamp, message)
	if err != nil {
		return nil, err
	}

	if err = IsValidID(clientID); err != nil {
		return nil, err
	}

	// sig should always be ed25519.SignatureSize=64 bytes
	sig := ed25519.Sign(edkey, message)

	protected := append(timestamp, clientID...)
	protected = append(protected, sig...)
	protected = append(protected, ct...)

	return protected, nil
}

// ProtectPubKeyFIPS protects a non-command messages using FIPS-compliant pubkey crypto
func ProtectPubKeyFIPS(message, key []byte, eckey *ecdsa.PrivateKey, clientID []byte) ([]byte, error) {

	timestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().Unix()))

	ct, err := Encrypt(key, timestamp, message)
	if err != nil {
		return nil, err
	}

	if err = IsValidID(clientID); err != nil {
		return nil, err
	}

	messagehash := sha256.Sum256(message)

	// sig should always be 64 bytes
	sig, err := ecdsa.Sign(rand.Reader, eckey, messagehash[:])

	protected := append(timestamp, clientID...)
	protected = append(protected, sig...)
	protected = append(protected, ct...)

	return protected, nil
}
