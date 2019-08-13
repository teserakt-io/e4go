package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestRandomID(t *testing.T) {
	zeroid := make([]byte, IDLen)

	for i := 0; i < 2048; i++ {
		randomidx := RandomID()
		randomidy := RandomID()

		if len(randomidx) != IDLen {
			t.Fatalf("expected ID length to be %d, got %d", IDLen, len(randomidx))
		}
		if len(randomidy) != IDLen {
			t.Fatalf("expected ID length to be %d, got %d", IDLen, len(randomidx))
		}

		if bytes.Equal(randomidx, zeroid) || bytes.Equal(randomidy, zeroid) {
			t.Fatalf("ID is all zeros, not random")
		}
		if bytes.Equal(randomidx, randomidy) {
			t.Fatalf("Two random IDs collide; not random")
		}
	}
}

/* Test encrypt tests KATs for the encryption code */
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
		t.Fatalf("encryption failed: %s", err)
	}
	if string(ct) != string(ctt) {
		t.Fatal("ciphertext doesn't match")
	}
}

/* TestRandom tests no trivial collisions exist, the correct
   length of data is generated and that random does not generate
   a zero key.

   TODO: proper random testing?
*/
func TestRandomKey(t *testing.T) {
	zeroes := make([]byte, KeyLen)

	for i := 0; i < 2048; i++ {
		k1 := RandomKey()
		k2 := RandomKey()

		if string(k1) == string(k2) {
			t.Fatal("RandomKey isn't random")
		}

		if len(k1) != KeyLen {
			t.Fatalf("random key of incorrect length, expected %d, got %d", KeyLen, len(k1))
		}
		if len(k2) != KeyLen {
			t.Fatalf("random key of incorrect length, expected %d, got %d", KeyLen, len(k1))
		}

		if string(k1) == string(zeroes) || string(k2) == string(zeroes) {
			t.Fatalf("randomness not random")
		}
	}
}

/* TestEncDec tests that we can return the same plaintext as
   we encrypted. In addition, it tests that modifications to
  associated data, ciphertext or key produce a failure result. */
func TestEncDec(t *testing.T) {
	for i := 0; i < 2048; i++ {

		rdelta := GetRDelta()

		ptLen := 1234 + rdelta

		key := make([]byte, KeyLen)
		ad := make([]byte, TimestampLen)
		pt := make([]byte, ptLen)

		rand.Read(key)
		rand.Read(ad)
		rand.Read(pt)

		ct, err := Encrypt(key, ad, pt)

		if err != nil {
			t.Fatalf("encryption failed: %s", err)
		}
		if len(ct) != len(pt)+TagLen {
			t.Fatalf("invalid ciphertext size: %d vs %d", len(ct), len(pt)+TagLen)
		}

		// happy case:
		ptt, err := Decrypt(key, ad, ct)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}
		if len(pt) != len(ptt) {
			t.Fatalf("decrypted message has different length than original: %d vs %d", len(ptt), len(pt))
		}

		if !bytes.Equal(pt, ptt) {
			t.Fatal("decrypted message different from the original")
		}

		// invalid ad:

		adinvalid := make([]byte, TimestampLen)
		copy(adinvalid, ad)
		for i := range adinvalid {
			adinvalid[i] ^= 0x01
		}

		_, err = Decrypt(key, adinvalid, ct)
		if err == nil {
			t.Fatal("invalid ad: decryption did not fail as expected.")
		}

		// invalid ciphertext
		ctlen := len(ct)
		ctinvalid := make([]byte, ctlen)
		copy(ctinvalid, ct)
		for i := range ctinvalid {
			ctinvalid[i] ^= 0x01
		}
		_, err = Decrypt(key, ad, ctinvalid)
		if err == nil {
			t.Fatal("invalid ct: decryption did not fail as expected.")
		}

		// invalid key should obviously not work either
		zerokey := make([]byte, KeyLen)
		for i := range zerokey {
			zerokey[i] = 0x00
		}

		if bytes.Equal(zerokey, key) {
			t.Fatal("key isn't random (all zeros), probably a failure")
		}

		_, err = Decrypt(zerokey, ad, ct)
		if err == nil {
			t.Fatal("invalid key: decryption did not fail as expected.")
		}

		// truncated/too short ciphertext
		truncct := ct[:2]
		_, err = Decrypt(key, ad, truncct)
		if err == nil {
			t.Fatal("invalid key: decryption did not fail as expected.")
		}
	}
}

func TestEncryptInvalidKeys(t *testing.T) {
	key := make([]byte, KeyLen)
	_, err := Encrypt(key, nil, nil)
	if err == nil {
		t.Fatal("expected an error when calling encrypt with zero key")
	}

	_, err = Encrypt(key[:len(key)-1], nil, nil)
	if err == nil {
		t.Fatal("expected an error when calling encrypt with too short key")
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

	if bytes.Equal(unprotected, payload) == false {
		t.Fatalf("Expected unprotected payload to be %v, got %v", payload, unprotected)
	}

	now := time.Now()
	timestamp := make([]byte, TimestampLen)

	// Replace timestamp in cipher by a too old timestamp
	pastTs := now.Add(time.Duration(-MaxSecondsDelay) * time.Second)
	binary.LittleEndian.PutUint64(timestamp, uint64(pastTs.Unix()))
	tooOldProtected := append(timestamp, protected[TimestampLen:]...)
	_, err = UnprotectSymKey(tooOldProtected, key)
	if err != ErrTimestampTooOld {
		t.Fatalf("Expected %v, got %v", ErrTimestampTooOld, err)
	}

	// Replace timestamp in cipher by a timestamp in futur
	futurTs := now.Add(1 * time.Second)
	binary.LittleEndian.PutUint64(timestamp, uint64(futurTs.Unix()))
	futurProtected := append(timestamp, protected[TimestampLen:]...)
	_, err = UnprotectSymKey(futurProtected, key)
	if err != ErrTimestampInFutur {
		t.Fatalf("Expected %v, got %v", ErrTimestampInFutur, err)
	}

	// Too short cipher are not allowed
	tooShortProtected := make([]byte, TimestampLen)
	_, err = UnprotectSymKey(tooShortProtected, key)
	if err != ErrTooShortCipher {
		t.Fatalf("Expected %v, got %v", ErrTooShortCipher, err)
	}

	if _, err := UnprotectSymKey(protected, []byte("not a key")); err == nil {
		t.Fatal("expected unprotectSymKey to fail with an invalid key")
	}

	if _, err := ProtectSymKey([]byte("message"), []byte("not a key")); err == nil {
		t.Fatal("expected protectSymKey to fail with an invalid key")
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
		t.Fatalf("failed to create private key from password: %v", err)
	}

	if bytes.Equal(expectedKey, key) == false {
		t.Fatalf("expected key to be %#v, got %#v", expectedKey, key)
	}

	_, err = Ed25519PrivateKeyFromPassword(strings.Repeat("a", MinPasswordLength-1))
	if err == nil {
		t.Fatal("expected an error with a too short password")
	}
}

func TestDeriveSymKey(t *testing.T) {
	_, err := DeriveSymKey(strings.Repeat("a", MinPasswordLength-1))
	if err == nil {
		t.Fatal("expected an error with too short password")
	}

	k, err := DeriveSymKey("testPasswordRandom")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(k) != KeyLen {
		t.Fatalf("expected key size to be %d, got %d", KeyLen, len(k))
	}
}
