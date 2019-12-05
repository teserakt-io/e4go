// Package crypto defines the cryptographic functions used in E4
package crypto

// Copyright 2018-2019-2020 Teserakt AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/agl/ed25519/extra25519"
	miscreant "github.com/miscreant/miscreant.go"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

var (
	// ErrInvalidProtectedLen occurs when the protected message is  not of the expected length
	ErrInvalidProtectedLen = errors.New("invalid length of protected message")
	// ErrTooShortCipher occurs when trying to unprotect a cipher shorter than TimestampLen
	ErrTooShortCipher = errors.New("ciphertext too short")
	// ErrTimestampInFuture occurs when the cipher timestamp is in the future
	ErrTimestampInFuture = errors.New("timestamp received is in the future")
	// ErrTimestampTooOld occurs when the cipher timestamp is older than MaxDelayDuration from now
	ErrTimestampTooOld = errors.New("timestamp too old")
	// ErrInvalidSignature occurs when a signature verification fails
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrInvalidSignerID occurs when trying to sign with an invalid ID
	ErrInvalidSignerID = errors.New("invalid signer ID")
	// ErrInvalidTimestamp occurs when trying to sign with an invalid timestamp
	ErrInvalidTimestamp = errors.New("invalid timestamp")
)

// Curve25519PublicKey defines a type for curve 25519 public keys
type Curve25519PublicKey []byte

// Curve25519PrivateKey defines a type for curve 25519 private keys
type Curve25519PrivateKey []byte

// Encrypt creates an authenticated ciphertext
func Encrypt(key, ad, pt []byte) ([]byte, error) {
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

// Decrypt decrypts and verifies an authenticated ciphertext
func Decrypt(key, ad, ct []byte) ([]byte, error) {
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

	return c.Open(nil, ct, ad)
}

// Sign will sign the given payload using the given privateKey,
// producing an output composed of: timestamp + signedID + payload + signature
func Sign(signerID []byte, privateKey ed25519.PrivateKey, timestamp []byte, payload []byte) ([]byte, error) {
	if len(signerID) != IDLen {
		return nil, ErrInvalidSignerID
	}

	if len(timestamp) != TimestampLen {
		return nil, ErrInvalidTimestamp
	}

	protected := append(timestamp, signerID...)
	protected = append(protected, payload...)

	// sig should always be ed25519.SignatureSize=64 bytes
	sig := ed25519.Sign(privateKey, protected)
	if len(sig) != ed25519.SignatureSize {
		return nil, ErrInvalidSignature
	}
	protected = append(protected, sig...)

	return protected, nil
}

// DeriveSymKey derives a symmetric key from a password using Argon2
// (Replaces HashPwd)
func DeriveSymKey(pwd string) ([]byte, error) {
	if err := ValidatePassword(pwd); err != nil {
		return nil, fmt.Errorf("invalid password: %v", err)
	}

	return argon2.Key([]byte(pwd), nil, 1, 64*1024, 4, KeyLen), nil
}

// ProtectSymKey attempt to encrypt payload using given symmetric key
func ProtectSymKey(payload, key []byte) ([]byte, error) {
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
func UnprotectSymKey(protected, key []byte) ([]byte, error) {
	if len(protected) <= TimestampLen+TagLen {
		return nil, ErrTooShortCipher
	}

	ct := protected[TimestampLen:]
	timestamp := protected[:TimestampLen]

	if err := ValidateTimestamp(timestamp); err != nil {
		return nil, err
	}

	pt, err := Decrypt(key, timestamp, ct)
	if err != nil {
		return nil, err
	}

	return pt, nil
}

// RandomKey generates a random KeyLen-byte key usable by Encrypt and Decrypt
func RandomKey() []byte {
	key := make([]byte, KeyLen)
	n, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	if n != KeyLen {
		panic(fmt.Errorf("bytes read mismatch in RandomKey: got %d wanted %d", n, KeyLen))
	}

	return key
}

// RandomCurve25519Keys generates Curve25519 public and private keys
func RandomCurve25519Keys() (Curve25519PublicKey, Curve25519PrivateKey, error) {
	privateKey := RandomKey()
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

// RandomID generates a random IDLen-byte ID
func RandomID() []byte {
	id := make([]byte, IDLen)
	n, err := rand.Read(id)
	if err != nil {
		panic(err)
	}
	if n != IDLen {
		panic(fmt.Errorf("bytes read mismatch in RandomID: got %d wanted %d", n, IDLen))
	}

	return id
}

// RandomDelta16 produces a random 16-bit integer to allow us to
// vary key sizes, plaintext sizes etc
func RandomDelta16() uint16 {
	randAdjust := make([]byte, 2)
	rand.Read(randAdjust)
	return binary.LittleEndian.Uint16(randAdjust)
}

// Ed25519PrivateKeyFromPassword creates a ed25519.PrivateKey from a password
func Ed25519PrivateKeyFromPassword(password string) (ed25519.PrivateKey, error) {
	if err := ValidatePassword(password); err != nil {
		return nil, fmt.Errorf("invalid password: %v", err)
	}

	seed := argon2.Key([]byte(password), nil, 1, 64*1024, 4, ed25519.SeedSize)
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublicEd25519KeyToCurve25519 convert an ed25519.PublicKey to a curve25519 public key.
func PublicEd25519KeyToCurve25519(edPubKey ed25519.PublicKey) Curve25519PublicKey {
	var edPk [32]byte
	var curveKey [32]byte
	copy(edPk[:], edPubKey)
	if !extra25519.PublicKeyToCurve25519(&curveKey, &edPk) {
		panic("could not convert ed25519 public key to curve25519")
	}

	return curveKey[:]
}

// PrivateEd25519KeyToCurve25519 convert an ed25519.PrivateKey to a curve25519 private key.
func PrivateEd25519KeyToCurve25519(edPrivKey ed25519.PrivateKey) Curve25519PrivateKey {
	var edSk [64]byte
	var curveKey [32]byte
	copy(edSk[:], edPrivKey)
	extra25519.PrivateKeyToCurve25519(&curveKey, &edSk)

	return curveKey[:]
}
