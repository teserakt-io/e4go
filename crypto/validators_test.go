package crypto

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
				t.Fatalf("Expected name '%s' validation to return no error, got %v", validName, err)
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
				t.Fatalf("Expected id '%v' validation to return no error, got %v", validID, err)
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
				t.Fatalf("Expected key '%v' validation to return no error, got %v", validKey, err)
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
				t.Fatalf("Expected key '%v' validation to return no error, got %v", validKey, err)
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
				t.Fatalf("Expected topic '%v' validation to return no error, got %v", validTopic, err)
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
				t.Fatalf("Expected topic hash '%v' validation to return no error, got %v", validTopic, err)
			}
		}
	})
}

func TestValidateTimestamp(t *testing.T) {
	futurTimestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(futurTimestamp, uint64(time.Now().Add(1*time.Second).Unix()))
	if err := ValidateTimestamp(futurTimestamp); err == nil {
		t.Fatalf("expected timestamp in futur to not be valid")
	}

	pastTimestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(pastTimestamp, uint64(time.Now().Add(-(MaxSecondsDelay + 1)).Unix()))
	if err := ValidateTimestamp(pastTimestamp); err == nil {
		t.Fatalf("expected timestamp too far in past to not be valid")
	}

	validTimestamp := make([]byte, TimestampLen)
	binary.LittleEndian.PutUint64(validTimestamp, uint64(time.Now().Unix()))
	if err := ValidateTimestamp(validTimestamp); err != nil {
		t.Fatalf("expected timestamp to be valid, got error: %v", err)
	}
}

func TestValidateCurve25519PubKey(t *testing.T) {
	t.Run("Invalid public keys return an error", func(t *testing.T) {
		allZeroKey := make([]byte, 32)

		tooLongKey := make([]byte, 33)
		rand.Read(tooLongKey)

		tooShortKey := make([]byte, 31)
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
		validKey := make([]byte, 32)
		rand.Read(validKey)

		validKeys := [][]byte{
			validKey,
		}

		for _, validKey := range validKeys {
			if err := ValidateCurve25519PubKey(validKey); err != nil {
				t.Fatalf("Expected key '%v' validation to return no error, got %v", validKey, err)
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
			strings.Repeat("a", MinPasswordLength-1),
		}
		for _, invalidPassword := range invalidPasswords {
			if err := ValidatePassword(invalidPassword); err == nil {
				t.Fatalf("Expected password '%s' validation to return an error", invalidPassword)
			}
		}
	})

	t.Run("Valid passwords return no error", func(t *testing.T) {
		validPasswords := []string{
			strings.Repeat("a", MinPasswordLength),
			"исследованиеание",
			"研究研究研究研究",
		}
		for _, validPassword := range validPasswords {
			if err := ValidatePassword(validPassword); err != nil {
				t.Fatalf("Expected name '%s' validation to return no error, got %v", validPassword, err)
			}
		}
	})
}
