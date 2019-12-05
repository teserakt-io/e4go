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
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
)

func TestValidateName(t *testing.T) {
	t.Run("Invalid names return errors", func(t *testing.T) {
		invalidNames := []string{
			"",
			string([]byte{0xfe}),
			string([]byte{0xff}),
			string([]byte{0xf8, 0x80, 0x80, 0x80}),
		}
		for _, invalidName := range invalidNames {
			if err := ValidateName(invalidName); err == nil {
				t.Fatalf("Expected name '%s' validation to return an error", invalidName)
			}
		}
	})

	t.Run("Valid names return no error", func(t *testing.T) {
		validNames := []string{
			"randomName",
			"исследование",
			"研究",
		}
		for _, validName := range validNames {
			if err := ValidateName(validName); err != nil {
				t.Fatalf("Got error %v when validating name '%s', wanted no error", err, validName)
			}
		}
	})
}

func TestValidateID(t *testing.T) {
	t.Run("Invalid ids return an error", func(t *testing.T) {
		invalidIDs := [][]byte{
			nil,
			[]byte{},
			make([]byte, IDLen-1),
			make([]byte, IDLen+1),
		}

		for _, invalidID := range invalidIDs {
			if err := ValidateID(invalidID); err == nil {
				t.Fatalf("Expected id '%v' validation to return an error", invalidID)
			}
		}
	})

	t.Run("Valid ids return no error", func(t *testing.T) {
		validIDs := [][]byte{
			make([]byte, IDLen),
		}

		for _, validID := range validIDs {
			if err := ValidateID(validID); err != nil {
				t.Fatalf("Got validation error %v when validating ID '%v', wanted no error", err, validID)
			}
		}
	})
}

func TestValidateEd25519PrivKey(t *testing.T) {
	t.Run("Invalid private keys return an error", func(t *testing.T) {
		allZeroKey := make(ed25519.PrivateKey, ed25519.PrivateKeySize)

		tooLongKey := make(ed25519.PrivateKey, ed25519.PrivateKeySize+1)
		rand.Read(tooLongKey)

		tooShortKey := make(ed25519.PrivateKey, ed25519.PrivateKeySize-1)
		rand.Read(tooShortKey)

		invalidKeys := []ed25519.PrivateKey{
			nil,
			allZeroKey,
			tooLongKey,
			tooShortKey,
		}

		for _, invalidKey := range invalidKeys {
			if err := ValidateEd25519PrivKey(invalidKey); err == nil {
				t.Fatalf("Expected key '%v' validation to return an error", invalidKey)
			}
		}
	})

	t.Run("Valid private keys return no error", func(t *testing.T) {
		validKey := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
		rand.Read(validKey)

		validKeys := [][]byte{
			validKey,
		}

		for _, validKey := range validKeys {
			if err := ValidateEd25519PrivKey(validKey); err != nil {
				t.Fatalf("Got error %v when validating key '%v', wanted no error", err, validKey)
			}
		}
	})
}

func TestValidEd25519PubKey(t *testing.T) {
	t.Run("Invalid public keys return an error", func(t *testing.T) {
		allZeroKey := make(ed25519.PublicKey, ed25519.PublicKeySize)

		tooLongKey := make(ed25519.PublicKey, ed25519.PublicKeySize+1)
		rand.Read(tooLongKey)

		tooShortKey := make(ed25519.PublicKey, ed25519.PublicKeySize-1)
		rand.Read(tooShortKey)

		invalidKeys := []ed25519.PublicKey{
			allZeroKey,
			tooLongKey,
			tooShortKey,
		}

		for _, invalidKey := range invalidKeys {
			if err := ValidateEd25519PubKey(invalidKey); err == nil {
				t.Fatalf("Expected key '%v' validation to return an error", invalidKey)
			}
		}
	})

	t.Run("Valid public keys return no error", func(t *testing.T) {
		validKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
		rand.Read(validKey)

		validKeys := [][]byte{
			validKey,
		}

		for _, validKey := range validKeys {
			if err := ValidateEd25519PubKey(validKey); err != nil {
				t.Fatalf("Got error %v when validating key '%v', wanted no error", err, validKey)
			}
		}
	})
}

func TestValidateTopic(t *testing.T) {
	t.Run("Invalid topics return an error", func(t *testing.T) {
		invalidTopics := []string{
			"",
			strings.Repeat("a", MaxTopicLen+1),
		}

		for _, invalidTopic := range invalidTopics {
			if err := ValidateTopic(invalidTopic); err == nil {
				t.Fatalf("Expected topic '%v' validation to return an error", invalidTopic)
			}
		}
	})

	t.Run("Valid topics return no error", func(t *testing.T) {
		validTopics := []string{
			strings.Repeat("a", MaxTopicLen),
			"a",
			"/some/topic",
		}

		for _, validTopic := range validTopics {
			if err := ValidateTopic(validTopic); err != nil {
				t.Fatalf("Got error %v when validating topic '%v', wanted no error", err, validTopic)
			}
		}
	})
}

func TestValidateTopicHash(t *testing.T) {
	t.Run("Invalid topic hashes return an error", func(t *testing.T) {
		tooShortHash := make([]byte, HashLen-1)
		tooLongHash := make([]byte, HashLen+1)

		invalidTopics := [][]byte{
			tooShortHash,
			tooLongHash,
		}

		for _, invalidTopic := range invalidTopics {
			if err := ValidateTopicHash(invalidTopic); err == nil {
				t.Fatalf("Expected topic '%v' validation to return an error", invalidTopic)
			}
		}
	})

	t.Run("Valid topic hashes return no error", func(t *testing.T) {
		allZeroHash := make([]byte, HashLen)

		randomHash := make([]byte, HashLen)
		rand.Read(randomHash)

		validTopics := [][]byte{
			allZeroHash,
			randomHash,
		}

		for _, validTopic := range validTopics {
			if err := ValidateTopicHash(validTopic); err != nil {
				t.Fatalf("Got error %v when validating topic hash '%v', wanted no error", err, validTopic)
			}
		}
	})
}

func TestValidateTimestamp(t *testing.T) {
	futureTimestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(futureTimestamp, uint64(time.Now().Add(1*time.Second).Unix()))
	if err := ValidateTimestamp(futureTimestamp); err != ErrTimestampInFuture {
		t.Fatalf("Expected timestamp in the future to not be valid: got %v, wanted %v", err, ErrTimestampInFuture)
	}

	pastTimestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(pastTimestamp, uint64(time.Now().Add(-(MaxDelayDuration + 1)).Unix()))
	if err := ValidateTimestamp(pastTimestamp); err != ErrTimestampTooOld {
		t.Fatalf("Expected timestamp too far in past to not be valid")
	}

	validTimestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(validTimestamp, uint64(time.Now().Unix()))
	if err := ValidateTimestamp(validTimestamp); err != nil {
		t.Fatalf("Got error %v when validating timestamp %v, wanted no error", err, validTimestamp)
	}
}

func TestValidateTimestampKey(t *testing.T) {
	futureTimestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(futureTimestamp, uint64(time.Now().Add(1*time.Second).Unix()))
	if err := ValidateTimestampKey(futureTimestamp); err != ErrTimestampInFuture {
		t.Fatalf("Expected timestamp in the future to not be valid: got %v, wanted %v", err, ErrTimestampInFuture)
	}

	pastTimestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(pastTimestamp, uint64(time.Now().Add(-(MaxDelayKeyTransition + 1)).Unix()))
	if err := ValidateTimestampKey(pastTimestamp); err != ErrTimestampTooOld {
		t.Fatalf("Expected timestamp too far in past to not be valid: got %v, wanted %v", err, ErrTimestampTooOld)
	}

	validTimestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(validTimestamp, uint64(time.Now().Unix()))
	if err := ValidateTimestampKey(validTimestamp); err != nil {
		t.Fatalf("Got error %v when validating timestamp %v, wanted no error", err, validTimestamp)
	}
}

func TestValidateCurve25519PubKey(t *testing.T) {
	t.Run("Invalid public keys return an error", func(t *testing.T) {
		allZeroKey := make([]byte, Curve25519PubKeyLen)

		tooLongKey := make([]byte, Curve25519PubKeyLen+1)
		rand.Read(tooLongKey)

		tooShortKey := make([]byte, Curve25519PubKeyLen-1)
		rand.Read(tooShortKey)

		invalidKeys := [][]byte{
			allZeroKey,
			tooLongKey,
			tooShortKey,
		}

		for _, invalidKey := range invalidKeys {
			if err := ValidateCurve25519PubKey(invalidKey); err == nil {
				t.Fatalf("Expected key '%v' validation to return an error", invalidKey)
			}
		}
	})

	t.Run("Valid public keys return no error", func(t *testing.T) {
		validKey := make([]byte, Curve25519PubKeyLen)
		rand.Read(validKey)

		validKeys := [][]byte{
			validKey,
		}

		for _, validKey := range validKeys {
			if err := ValidateCurve25519PubKey(validKey); err != nil {
				t.Fatalf("Got error %v when validating key '%v', wanted no error", err, validKey)
			}
		}
	})
}

func TestValidateCurve25519PrivKey(t *testing.T) {
	t.Run("Invalid private keys return an error", func(t *testing.T) {
		allZeroKey := make([]byte, Curve25519PrivKeyLen)

		tooLongKey := make([]byte, Curve25519PrivKeyLen+1)
		rand.Read(tooLongKey)

		tooShortKey := make([]byte, Curve25519PrivKeyLen-1)
		rand.Read(tooShortKey)

		invalidKeys := [][]byte{
			allZeroKey,
			tooLongKey,
			tooShortKey,
		}

		for _, invalidKey := range invalidKeys {
			if err := ValidateCurve25519PrivKey(invalidKey); err == nil {
				t.Fatalf("Expected key '%v' validation to return an error", invalidKey)
			}
		}
	})

	t.Run("Valid private keys return no error", func(t *testing.T) {
		validKey := make([]byte, Curve25519PrivKeyLen)
		rand.Read(validKey)

		validKeys := [][]byte{
			validKey,
		}

		for _, validKey := range validKeys {
			if err := ValidateCurve25519PrivKey(validKey); err != nil {
				t.Fatalf("Got error %v when validating key '%v', wanted no error", err, validKey)
			}
		}
	})
}

func TestValidatePassword(t *testing.T) {
	t.Run("Invalid passwords return errors", func(t *testing.T) {
		invalidPasswords := []string{
			"",
			string([]byte{0xfe}),
			string([]byte{0xff}),
			string([]byte{0xf8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}),
			strings.Repeat("a", PasswordMinLength-1),
		}
		for _, invalidPassword := range invalidPasswords {
			if err := ValidatePassword(invalidPassword); err == nil {
				t.Fatalf("Expected password '%s' validation to return an error", invalidPassword)
			}
		}
	})

	t.Run("Valid passwords return no error", func(t *testing.T) {
		validPasswords := []string{
			strings.Repeat("a", PasswordMinLength),
			"исследованиеание",
			"研究研究研究研究",
		}
		for _, validPassword := range validPasswords {
			if err := ValidatePassword(validPassword); err != nil {
				t.Fatalf("Got error %v when validating password '%s', wanted no error", err, validPassword)
			}
		}
	})
}
