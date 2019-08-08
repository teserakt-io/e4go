package crypto

import (
	"encoding/hex"
	"testing"
)

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
