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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ed25519"
)

const (
	// PasswordMinLength defines the minimum size accepted for a password
	PasswordMinLength = 16
	// NameMinLen is the minimum length of a name
	NameMinLen = 1
	// NameMaxLen is the maximum length of a name
	NameMaxLen = 255
)

var (
	blankEd25519pk [ed25519.PublicKeySize]byte
	zeroEd25519pk  = blankEd25519pk[:]
	blankEd25519sk [ed25519.PrivateKeySize]byte
	zeroEd25519sk  = blankEd25519sk[:]

	blankCurve25519pk [Curve25519PubKeyLen]byte
	blankCurve25519sk [Curve25519PrivKeyLen]byte
	zeroCurve25519pk  = blankCurve25519pk[:]
	zeroCurve25519sk  = blankCurve25519sk[:]

	blankSymKey [KeyLen]byte
	zeroSymKey  = blankSymKey[:]
)

// ValidateSymKey checks that a key is of the expected length
// and not filled with zero
func ValidateSymKey(key []byte) error {
	if g, w := len(key), KeyLen; g != w {
		return fmt.Errorf("invalid symmetric key length, got %d, expected %d", g, w)
	}

	if bytes.Equal(zeroSymKey, key) {
		return errors.New("invalid symmetric key, all zeros")
	}

	return nil
}

// ValidateEd25519PrivKey checks that a key is of the expected length and not all zero
func ValidateEd25519PrivKey(key []byte) error {
	if g, w := len(key), ed25519.PrivateKeySize; g != w {
		return fmt.Errorf("invalid private key length, got %d, expected %d", g, w)
	}

	if bytes.Equal(zeroEd25519sk, key) {
		return errors.New("invalid private key, all zeros")
	}

	return nil
}

// ValidateEd25519PubKey checks that a key is of the expected length and not all zero
func ValidateEd25519PubKey(key []byte) error {
	if g, w := len(key), ed25519.PublicKeySize; g != w {
		return fmt.Errorf("invalid public key length, got %d, expected %d", g, w)
	}

	if bytes.Equal(zeroEd25519pk, key) {
		return errors.New("invalid public key, all zeros")
	}

	return nil
}

// ValidateCurve25519PubKey checks that a key is of the expected length and not all zero
func ValidateCurve25519PubKey(key []byte) error {
	if g, w := len(key), Curve25519PubKeyLen; g != w {
		return fmt.Errorf("invalid public key length, got %d, expected %d", g, w)
	}

	if bytes.Equal(zeroCurve25519pk, key) {
		return errors.New("invalid public key, all zeros")
	}

	return nil
}

// ValidateCurve25519PrivKey checks that a key is of the expected length and not all zero
func ValidateCurve25519PrivKey(key []byte) error {
	if g, w := len(key), Curve25519PrivKeyLen; g != w {
		return fmt.Errorf("invalid private key length, got %d, expected %d", g, w)
	}

	if bytes.Equal(zeroCurve25519sk, key) {
		return errors.New("invalid private key, all zeros")
	}

	return nil
}

// ValidateID checks that an id is of the expected length
func ValidateID(id []byte) error {
	if g, w := len(id), IDLen; g != w {
		return fmt.Errorf("invalid ID length, got %d, expected %d", g, w)
	}

	return nil
}

// ValidateName is used to validate names match given constraints
// since we hash these in the protocol, those constraints are quite
// liberal, but for correctness we check any string is valid UTF-8
func ValidateName(name string) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("name is not a valid UTF-8 string")
	}

	namelen := len(name)
	if namelen < NameMinLen || namelen > NameMaxLen {
		return fmt.Errorf("name length is invalid, names are between %d and %d characters", NameMinLen, NameMaxLen)
	}

	return nil
}

// ValidateTopic checks if a topic is not too large or empty
func ValidateTopic(topic string) error {
	if len(topic) > MaxTopicLen {
		return fmt.Errorf("topic too long, expected %d chars maximum, got %d", MaxTopicLen, len(topic))
	}

	if len(topic) == 0 {
		return errors.New("topic cannot be empty")
	}

	return nil
}

// ValidateTopicHash checks that a topic hash is of the expected length
func ValidateTopicHash(topicHash []byte) error {
	if g, w := len(topicHash), HashLen; g != w {
		return fmt.Errorf("invalid Topic Hash length, got %d, expected %d", g, w)
	}

	return nil
}

// ValidateTimestamp checks that given timestamp bytes are
// a valid LittleEndian encoded timestamp, not in the future and not older than MaxDelayDuration
func ValidateTimestamp(timestamp []byte) error {
	now := time.Now()
	tsTime := time.Unix(int64(binary.LittleEndian.Uint64(timestamp)), 0)

	if now.Before(tsTime) {
		return ErrTimestampInFuture
	}

	leastValidTime := now.Add(-MaxDelayDuration)
	if leastValidTime.After(tsTime) {
		return ErrTimestampTooOld
	}

	return nil
}

// ValidateTimestampKey checks that given timestamp bytes are
// a valid LittleEndian encoded timestamp, not in the future and not older than MaxDelayKeyTransition
func ValidateTimestampKey(timestamp []byte) error {
	now := time.Now()
	tsTime := time.Unix(int64(binary.LittleEndian.Uint64(timestamp)), 0)
	if now.Before(tsTime) {
		return ErrTimestampInFuture
	}

	leastValidTime := now.Add(-MaxDelayKeyTransition)
	if leastValidTime.After(tsTime) {
		return ErrTimestampTooOld
	}

	return nil
}

// ValidatePassword checks given password is an utf8 string of at least PasswordMinLength characters
func ValidatePassword(password string) error {
	if !utf8.ValidString(password) {
		return errors.New("password is not a valid UTF-8 string")
	}

	if len(password) < PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters", PasswordMinLength)
	}

	return nil
}
