package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/ed25519"
)

func TestRandomID(t *testing.T) {
	zeroID := make([]byte, IDLen)

	for i := 0; i < 2048; i++ {
		randomID1 := RandomID()
		randomID2 := RandomID()

		if len(randomID1) != IDLen {
			t.Fatalf("Unexpected ID length, got %d, expected %d", len(randomID1), IDLen)
		}
		if len(randomID2) != IDLen {
			t.Fatalf("Unexpected ID length, got %d, expected %d", len(randomID2), IDLen)
		}

		if bytes.Equal(randomID1, zeroID) || bytes.Equal(randomID2, zeroID) {
			t.Fatal("Random ID is all zeros, not random")
		}
		if bytes.Equal(randomID1, randomID2) {
			t.Fatal("2 random IDs must not be equals")
		}
	}
}

// Test encrypt tests KATs for the encryption code
func TestEncrypt(t *testing.T) {
	ptLen := 64
	adLen := 8

	key := make([]byte, KeyLen)
	pt := make([]byte, ptLen)
	ad := make([]byte, adLen)
	ctt := []byte{163, 170, 113, 22, 250, 77, 249, 210, 78, 28, 160, 45, 237, 93, 164, 200, 69, 177, 144, 88, 25, 34, 203, 0, 222, 9, 31, 200, 251, 127, 6, 91, 145, 230, 145, 187, 85, 154, 214, 154, 130, 152, 98, 74, 163, 29, 244, 187, 138, 58, 140, 254, 85, 107, 236, 245, 212, 233, 150, 187, 147, 172, 20, 22, 177, 76, 75, 137, 57, 249, 110, 197, 218, 174, 34, 208, 235, 228, 175, 83}

	for i := 0; i < KeyLen; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < ptLen; i++ {
		pt[i] = byte(i)
	}
	for i := 0; i < adLen; i++ {
		ad[i] = byte(i)
	}
	ct, err := Encrypt(key, ad, pt)
	if err != nil {
		t.Fatalf("Encryption failed: %s", err)
	}
	if !bytes.Equal(ct, ctt) {
		t.Fatalf("Ciphertext doesn't match. Got %v, expected %v", ct, ctt)
	}
}

// TestRandom tests no trivial collisions exist, the correct
// length of data is generated and that random does not generate
// a zero key.
// TODO: proper random testing?
func TestRandomKey(t *testing.T) {
	zeroes := make([]byte, KeyLen)

	for i := 0; i < 2048; i++ {
		k1 := RandomKey()
		k2 := RandomKey()

		if bytes.Equal(k1, k2) {
			t.Fatal("2 random keys must not be equals")
		}

		if len(k1) != KeyLen {
			t.Fatalf("Incorrect random key length, got %d, expected %d", len(k1), KeyLen)
		}
		if len(k2) != KeyLen {
			t.Fatalf("Incorrect random key length, got %d, expected %d", len(k2), KeyLen)
		}

		if bytes.Equal(k1, zeroes) || bytes.Equal(k2, zeroes) {
			t.Fatal("Random key is all zeros, not random")
		}
	}
}

// TestEncryptDecrypt tests that we can return the same plaintext as
// we encrypted. In addition, it tests that modifications to
// associated data, ciphertext or key produce a failure result.
func TestEncryptDecrypt(t *testing.T) {
	for i := 0; i < 2048; i++ {

		rDelta := RandomDelta16()

		ptLen := 1234 + rDelta

		key := make([]byte, KeyLen)
		ad := make([]byte, TimestampLen)
		pt := make([]byte, ptLen)

		rand.Read(key)
		rand.Read(ad)
		rand.Read(pt)

		ct, err := Encrypt(key, ad, pt)

		if err != nil {
			t.Fatalf("Encryption failed: %s", err)
		}
		if len(ct) != len(pt)+TagLen {
			t.Fatalf("Invalid ciphertext size: got: %d, wanted: %d", len(ct), len(pt)+TagLen)
		}

		// happy case:
		ptt, err := Decrypt(key, ad, ct)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if len(ptt) != len(pt) {
			t.Fatalf("Decrypted message has different length than original: got: %d, wanted: %d", len(ptt), len(pt))
		}

		if !bytes.Equal(ptt, pt) {
			t.Fatalf("Invalid decrypted message, got %v, wanted %v", ptt, pt)
		}

		// invalid ad:
		adInvalid := make([]byte, TimestampLen)
		copy(adInvalid, ad)
		for i := range adInvalid {
			adInvalid[i] ^= 0x01
		}

		_, err = Decrypt(key, adInvalid, ct)
		if err == nil {
			t.Fatal("Expected a decryption error with an invalid ad.")
		}

		// invalid ciphertext
		ctLength := len(ct)
		ctInvalid := make([]byte, ctLength)
		copy(ctInvalid, ct)
		for i := range ctInvalid {
			ctInvalid[i] ^= 0x01
		}
		_, err = Decrypt(key, ad, ctInvalid)
		if err == nil {
			t.Fatal("Expected a decryption error with an invalid ct.")
		}

		// invalid key should obviously not work either
		zeroKey := make([]byte, KeyLen)
		_, err = Decrypt(zeroKey, ad, ct)
		if err == nil {
			t.Fatal("Expected a decryption error with an invalid key.")
		}

		// truncated/too short ciphertext
		truncatedCt := ct[:2]
		_, err = Decrypt(key, ad, truncatedCt)
		if err == nil {
			t.Fatal("Expected a decryption error with a truncated ct.")
		}
	}
}

func TestEncryptInvalidKeys(t *testing.T) {
	key := make([]byte, KeyLen)
	_, err := Encrypt(key, nil, nil)
	if err == nil {
		t.Fatal("Expected an error when calling encrypt with zero key")
	}

	_, err = Encrypt(key[:len(key)-1], nil, nil)
	if err == nil {
		t.Fatal("Expected an error when calling encrypt with a too short key")
	}
}

func TestProtectUnprotectSymKey(t *testing.T) {
	payload := []byte("some test payload")
	key := RandomKey()

	protected, err := ProtectSymKey(payload, key)
	if err != nil {
		t.Fatalf("ProtectSymKey failed: %v", err)
	}

	unprotected, err := UnprotectSymKey(protected, key)
	if err != nil {
		t.Fatalf("UnprotectSymKey failed: %v", err)
	}

	if !bytes.Equal(unprotected, payload) {
		t.Fatalf("Invalid unprotected payload: got: %v, wanted: %v", unprotected, payload)
	}

	now := time.Now()
	timestamp := make([]byte, TimestampLen)

	// Replace timestamp in cipher by a too old timestamp
	pastTs := now.Add(time.Duration(-MaxDelayDuration))
	binary.LittleEndian.PutUint64(timestamp, uint64(pastTs.Unix()))
	tooOldProtected := append(timestamp, protected[TimestampLen:]...)
	_, err = UnprotectSymKey(tooOldProtected, key)
	if err != ErrTimestampTooOld {
		t.Fatalf("Invalid error, got: %v, wanted: %v", err, ErrTimestampTooOld)
	}

	// Replace timestamp in cipher by a timestamp in future
	futureTs := now.Add(1 * time.Second)
	binary.LittleEndian.PutUint64(timestamp, uint64(futureTs.Unix()))
	futureProtected := append(timestamp, protected[TimestampLen:]...)
	_, err = UnprotectSymKey(futureProtected, key)
	if err != ErrTimestampInFuture {
		t.Fatalf("Invalid error, got: %v, wanted: %v", err, ErrTimestampInFuture)
	}

	// Too short cipher are not allowed
	tooShortProtected := make([]byte, TimestampLen)
	_, err = UnprotectSymKey(tooShortProtected, key)
	if err != ErrTooShortCipher {
		t.Fatalf("Invalid error, got: %v, wanted: %v", err, ErrTooShortCipher)
	}

	if _, err := UnprotectSymKey(protected, []byte("not a key")); err == nil {
		t.Fatal("Expected unprotectSymKey to fail with an invalid key")
	}

	if _, err := ProtectSymKey([]byte("message"), []byte("not a key")); err == nil {
		t.Fatal("Expected protectSymKey to fail with an invalid key")
	}
}

func TestEd25519PrivateKeyFromPassword(t *testing.T) {
	password := "some random password"
	expectedKey := []byte{
		0xb7, 0x5a, 0x20, 0xc3, 0x9f, 0xeb, 0x46, 0xd1, 0x89, 0xa8, 0x78, 0x4e, 0xda, 0x1a, 0x36, 0x6a, 0xa3, 0xea, 0x8d,
		0xf4, 0x4f, 0xc5, 0xb7, 0xfd, 0x63, 0x4d, 0xa4, 0xd7, 0xe4, 0xaf, 0x98, 0xbe, 0x4f, 0x2e, 0x32, 0xfa, 0xdf, 0xc2,
		0xb2, 0xab, 0x98, 0x2f, 0xd7, 0xc, 0xb0, 0xfa, 0x3b, 0x98, 0x5f, 0x71, 0x8, 0x14, 0x56, 0x9c, 0x73, 0xfe, 0xd8,
		0x67, 0x82, 0xf2, 0xd5, 0x29, 0x73, 0x58,
	}

	key, err := Ed25519PrivateKeyFromPassword(password)
	if err != nil {
		t.Fatalf("Failed to create private key from password: %v", err)
	}

	if !bytes.Equal(expectedKey, key) {
		t.Fatalf("Invalid key, got: %v, wanted: %v", key, expectedKey)
	}

	_, err = Ed25519PrivateKeyFromPassword(strings.Repeat("a", PasswordMinLength-1))
	if err == nil {
		t.Fatal("Expected an error with a too short password")
	}
}

func TestDeriveSymKey(t *testing.T) {
	_, err := DeriveSymKey(strings.Repeat("a", PasswordMinLength-1))
	if err == nil {
		t.Fatal("Expected an error with too short password")
	}

	k, err := DeriveSymKey("testPasswordRandom")
	if err != nil {
		t.Fatalf("DeriveSymKey error, got: %v, wanted nil", err)
	}

	if len(k) != KeyLen {
		t.Fatalf("Invalid key length: got: %d, wanted: %d", len(k), KeyLen)
	}
}

func TestPublicEd25519KeyToCurve25519(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	var pk [32]byte
	copy(pk[:], pubKey)

	var expectedCurveKey [32]byte
	extra25519.PublicKeyToCurve25519(&expectedCurveKey, &pk)

	curveKey := PublicEd25519KeyToCurve25519(pubKey)
	if curveKey != expectedCurveKey {
		t.Fatalf("Invalid curveKey, got %x, wanted %x", curveKey, expectedCurveKey)
	}
}

func TestPrivateEd25519KeyToCurve25519(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	var sk [64]byte
	copy(sk[:], privKey)

	var expectedCurveKey [32]byte
	extra25519.PrivateKeyToCurve25519(&expectedCurveKey, &sk)

	curveKey := PrivateEd25519KeyToCurve25519(privKey)
	if curveKey != expectedCurveKey {
		t.Fatalf("Invalid curveKey, got %x, wanted %x", curveKey, expectedCurveKey)
	}
}
