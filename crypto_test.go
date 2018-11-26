package e4common

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestHash(t *testing.T) {

	h := hex.EncodeToString(HashIDAlias("abc"))
	if h != "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" {
		t.Fatalf("hash of ID alias incorrect")
	}
	h = hex.EncodeToString(HashPwd("abc"))
	if h != "5b0ae13b530f55d44acbb89351b95d5bc64d9920ba3e8eef54044db9a8fd7a64e9fb11d7f04b4fce3c835698299c0fedf867b05ae886255c800a879e0a0ff775" {
		t.Fatalf("hash of password incorrect")
	}

}

func TestRandom(t *testing.T) {
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

func TestEncDec(t *testing.T) {

	ptLen := 1234

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
}

func TestProtectUnprotect(t *testing.T) {

	msgLen := 123

	key := make([]byte, KeyLen)
	msg := make([]byte, msgLen)

	rand.Read(key)
	rand.Read(msg)

	protected, err := Protect(msg, key)
	if err != nil {
		t.Fatalf("protect failed: %s", err)
	}

	unprotected, err := Unprotect(protected, key)
	if err != nil {
		t.Fatalf("unprotect failed: %s", err)
	}
	if !bytes.Equal(unprotected, msg) {
		t.Fatalf("unprotected message different from the original")
	}
}

func TestEncrypt(t *testing.T) {

	ptLen := 64
	adLen := 8

	key := make([]byte, KeyLen)
	pt := make([]byte, ptLen)
	ad := make([]byte, adLen)
	ctt := []byte{163, 170, 113, 22, 250, 77, 249, 210, 78, 28, 160, 45, 237, 93, 164, 200, 239, 32, 170, 161, 67, 210, 209, 143, 206, 227, 56, 153, 89, 63, 105, 243, 212, 68, 150, 83, 214, 188, 67, 40, 124, 247, 11, 3, 36, 146, 111, 176, 104, 213, 152, 36, 136, 233, 234, 238, 103, 167, 49, 182, 211, 77, 82, 130, 240, 196, 174, 235, 101, 183, 104, 189, 60, 240, 96, 15, 71, 147, 9, 43}

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
