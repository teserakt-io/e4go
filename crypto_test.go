package e4common

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
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
	h = hex.EncodeToString(HashPwd("abc"))
	if h != "5b0ae13b530f55d44acbb89351b95d5bc64d9920ba3e8eef54044db9a8fd7a64e9fb11d7f04b4fce3c835698299c0fedf867b05ae886255c800a879e0a0ff775" {
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

/* TestProtectUnprotect is an equivalent function to TestEncDec,
   except it works as the E4 API level. Tests that we can retrieve valid
   plaintext and also tests the E4 API is resistant to modification. */
func TestProtectUnprotect(t *testing.T) {

	for i := 0; i < 2048; i++ {
		rdelta := getRDelta()
		msgLen := 123 + rdelta

		key := make([]byte, KeyLen)
		msg := make([]byte, msgLen)

		rand.Read(key)
		rand.Read(msg)

		protected, err := Protect(msg, key)
		if err != nil {
			t.Fatalf("protect failed: %s", err)
		}

		protectedlen := msgLen + TagLen + TimestampLen

		// happy case.
		unprotected, err := Unprotect(protected, key)
		if err != nil {
			t.Fatalf("unprotect failed: %s", err)
		}
		if !bytes.Equal(unprotected, msg) {
			t.Fatalf("unprotected message different from the original")
		}

		// wrong ciphertext:

		invalidprotected := make([]byte, msgLen)
		copy(invalidprotected, protected)
		for i := range invalidprotected {
			invalidprotected[i] ^= 0x02
		}

		_, err = Unprotect(invalidprotected, key)
		if err == nil {
			t.Fatalf("Ciphertext changed: decryption did not fail as expected")
		}

		// invalid key
		invalidkey := make([]byte, KeyLen)
		copy(invalidkey, key)
		for i := range invalidkey {
			invalidkey[i] ^= 0x03
		}

		_, err = Unprotect(protected, invalidkey)
		if err == nil {
			t.Fatalf("Ciphertext changed: decryption did not fail as expected")
		}

		// future timestamp and past timestamp
		timestamporig := protected[:TimestampLen]
		ts := binary.LittleEndian.Uint64(timestamporig)
		tsf := ts + 1000000
		tsp := ts - (MaxSecondsDelay + 1)
		tsfuture := make([]byte, 8)
		tspast := make([]byte, 8)
		binary.LittleEndian.PutUint64(tsfuture, tsf)
		binary.LittleEndian.PutUint64(tspast, tsp)

		futureinvalidprotect := make([]byte, protectedlen)
		pastinvalidprotect := make([]byte, protectedlen)
		copy(futureinvalidprotect, tsfuture)
		copy(pastinvalidprotect, tspast)
		copy(futureinvalidprotect[TimestampLen:], protected[TimestampLen:])
		copy(pastinvalidprotect[TimestampLen:], protected[TimestampLen:])

		_, err = Unprotect(futureinvalidprotect, invalidkey)
		if err == nil {
			t.Fatalf("timestamp in future: decryption did not fail as expected")
		}

		_, err = Unprotect(pastinvalidprotect, invalidkey)
		if err == nil {
			t.Fatalf("timestamp too old: decryption did not fail as expected")
		}

	}
}
