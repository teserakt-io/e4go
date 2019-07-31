package e4common

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/ed25519"
)

/* getRDelta produces a random 16-bit integer to allow us to
   vary key sizes, plaintext sizes etc. */
func getRDelta() uint16 {
	randadjust := make([]byte, 2)
	rand.Read(randadjust)
	return binary.LittleEndian.Uint16(randadjust)
}

/* TestHash tests KATs for both the hash function of choice and
 * the password hashing function / KDF of choice */
func TestHash(t *testing.T) {

	h := hex.EncodeToString(HashIDAlias("abc"))
	if h != "3a985da74fe225b2045c172d6bd390bd" {
		t.Fatalf("hash of ID alias incorrect")
	}
	h = hex.EncodeToString(DeriveSymKey("abc"))
	if h != "fe8062b1208c8c97637810bdc2c668a3a8224f5e30fbeb13cb1508c4a4a7269a" {
		t.Fatalf("hash of password incorrect")
	}

}

func TestRandomID(t *testing.T) {
	for i := 0; i < 2048; i++ {
		zeroid := make([]byte, IDLen)
		randomidx := RandomID()
		randomidy := RandomID()
		if bytes.Equal(randomidx, zeroid) {
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
func TestRandom(t *testing.T) {

	for i := 0; i < 2048; i++ {
		zeroes := make([]byte, KeyLen)
		k1 := RandomKey()
		k2 := RandomKey()
		if string(k1) == string(k2) {
			t.Fatalf("RandomKey isn't random")
		}
		if len(k1) != KeyLen || len(k2) != KeyLen {
			t.Fatalf("random key of incorrect length")
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

		rdelta := getRDelta()

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
			t.Fatalf("decryption failed: %s", err)
		}
		if len(pt) != len(ptt) {
			t.Fatalf("decrypted message has different length than original: %d vs %d", len(ptt), len(pt))
		}

		if !bytes.Equal(pt, ptt) {
			t.Fatalf("decrypted message different from the original")
		}

		// invalid ad:

		adinvalid := make([]byte, TimestampLen)
		copy(adinvalid, ad)
		for i := range adinvalid {
			adinvalid[i] ^= 0x01
		}

		_, err = Decrypt(key, adinvalid, ct)
		if err == nil {
			t.Fatalf("invalid ad: decryption did not fail as expected.")
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
			t.Fatalf("invalid ct: decryption did not fail as expected.")
		}

		// invalid key should obviously not work either
		zerokey := make([]byte, KeyLen)
		for i := range zerokey {
			zerokey[i] = 0x00
		}

		if bytes.Equal(zerokey, key) {
			t.Fatalf("key isn't random (all zeros), probably a failure")
		}

		_, err = Decrypt(zerokey, ad, ct)
		if err == nil {
			t.Fatalf("invalid key: decryption did not fail as expected.")
		}

		// truncated/too short ciphertext
		truncct := ct[:2]
		_, err = Decrypt(key, ad, truncct)
		if err == nil {
			t.Fatalf("invalid key: decryption did not fail as expected.")
		}
	}
}

func TestProtectUnprotectCommandsSymKey(t *testing.T) {

}

func TestProtectUnprotectCommandsPubKey(t *testing.T) {

	filePath := "./test/data/clienttestcommand"

	protocol := PubKey

	c, err := NewClient(nil, nil, nil, filePath, protocol)

	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	var cpk [32]byte
	copy(cpk[:], c.Ed25519Key[32:])

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	var c2edsk [64]byte
	var c2edpk [32]byte
	var c2pk [32]byte
	var c2sk [32]byte
	copy(c2edsk[:], sk)
	copy(c2edpk[:], sk[32:])

	extra25519.PublicKeyToCurve25519(&c2pk, &c2edpk)
	extra25519.PrivateKeyToCurve25519(&c2sk, &c2edsk)

	command := make([]byte, 64)
	rand.Read(command)

	c.C2Key = &c2pk

	protected, err := ProtectCommandPubKey(command, &cpk, &c2sk)

	if err != nil {
		t.Fatalf("ProtectCommandPubKey failed: %v", err)
	}

	res, err := c.Unprotect(protected, c.ReceivingTopic)
	if res != nil {
		t.Fatalf("Unprotect returned non-nil value")
	}
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}

	// TODO: check processing of command with real command
}
