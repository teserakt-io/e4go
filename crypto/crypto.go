package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"

	miscreant "github.com/miscreant/miscreant/go"
)

var (
	// ErrInvalidProtectedLen occurs when the protected message is  not of the expected length.
	ErrInvalidProtectedLen = errors.New("invalid length of protected message")
)

// Encrypt creates an authenticated ciphertext.
func Encrypt(key []byte, ad []byte, pt []byte) ([]byte, error) {
	if err := ValidateSymKey(key); err != nil {
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
	if err := ValidateSymKey(key); err != nil {
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

// ProtectCommandPubKey is called by C2, not clients
func ProtectCommandPubKey(command []byte, clientpk, c2sk *[32]byte) ([]byte, error) {
	var shared [32]byte
	curve25519.ScalarMult(&shared, c2sk, clientpk)

	key := HashStuff(shared[:])[:KeyLen]

	return ProtectSymKey(command, key)
}

// DeriveSymKey derives a symmetric key from a password using Argon2.
// (Replaces HashPwd)
func DeriveSymKey(pwd string) []byte {
	return argon2.Key([]byte(pwd), nil, 1, 64*1024, 4, KeyLen)
}

// ProtectSymKey attempt to encrypt payload using given symmetric key
func ProtectSymKey(payload []byte, key []byte) ([]byte, error) {
	timestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().Unix()))

	ct, err := Encrypt(key, timestamp, payload)
	if err != nil {
		return nil, err
	}
	protected := append(timestamp, ct...)

	protectedLen := TimestampLen + len(payload) + TagLen
	if protectedLen != len(protected) {
		return nil, ErrInvalidProtectedLen
	}

	return protected, nil
}

// UnprotectSymKey attempt to decrypt protected bytes, using given symmetric key
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

// GetRDelta produces a random 16-bit integer to allow us to
// vary key sizes, plaintext sizes etc.
func GetRDelta() uint16 {
	randadjust := make([]byte, 2)
	rand.Read(randadjust)
	return binary.LittleEndian.Uint16(randadjust)
}
