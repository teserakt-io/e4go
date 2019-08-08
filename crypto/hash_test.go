package crypto

import (
	"encoding/hex"
	"testing"
)

/* TestHash tests KATs for both the hash function of choice and
 * the password hashing function / KDF of choice */
func TestHash(t *testing.T) {
	h := hex.EncodeToString(HashIDAlias("abc"))
	expected := "3a985da74fe225b2045c172d6bd390bd"
	if h != expected {
		t.Fatalf("hash of ID alias incorrect, expected %s, got %s", expected, h)
	}

	h = hex.EncodeToString(DeriveSymKey("abc"))
	expected = "fe8062b1208c8c97637810bdc2c668a3a8224f5e30fbeb13cb1508c4a4a7269a"
	if h != expected {
		t.Fatalf("hash of password incorrect, expected %s, got %s", expected, h)
	}

	h = hex.EncodeToString(HashTopic("abc"))
	expected = "3a985da74fe225b2045c172d6bd390bd"
	if h != expected {
		t.Fatalf("hash of Topic incorrect, expected %s, got %s", expected, h)
	}
}
