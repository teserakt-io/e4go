package keys

import (
	"bytes"
	"testing"

	e4crypto "gitlab.com/teserakt/e4common/crypto"
	"golang.org/x/crypto/ed25519"
)

func TestNewEd25519Key(t *testing.T) {
	expectedSignerID := e4crypto.HashIDAlias("test")
	_, expectedPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 private key: %v", err)
	}

	expectedC2PubKey := getTestC2PublicKey(t)

	key, err := NewEd25519Key(expectedSignerID, expectedPrivateKey, expectedC2PubKey)
	if err != nil {
		t.Fatalf("expected no error creating a key, got %v", err)
	}

	assertKeyContains(t, key, expectedSignerID, expectedPrivateKey, expectedC2PubKey)

	invalidSignerID := make([]byte, e4crypto.IDLen-1)
	_, err = NewEd25519Key(invalidSignerID, expectedPrivateKey, expectedC2PubKey)
	if err == nil {
		t.Fatal("expected invalid signerID to produce an error")
	}

	invalidPrivateKey := make([]byte, len(expectedPrivateKey))
	_, err = NewEd25519Key(expectedSignerID, invalidPrivateKey, expectedC2PubKey)
	if err == nil {
		t.Fatal("expected invalid private key to produce an error")
	}
}

func TestNewEd25519KeyFromPassword(t *testing.T) {
	password := "test-password"

	expectedSignerID := e4crypto.HashIDAlias("test")
	expectedC2PubKey := getTestC2PublicKey(t)

	key, err := NewEd25519KeyFromPassword(expectedSignerID, password, expectedC2PubKey)
	if err != nil {
		t.Fatalf("expected no error creating a key, got %v", err)
	}

	expectedPrivateKey := e4crypto.Ed25519PrivateKeyFromPassword(password)
	assertKeyContains(t, key, expectedSignerID, expectedPrivateKey, expectedC2PubKey)
}

func assertKeyContains(t *testing.T, key Ed25519Key, expectedSignerID []byte, expectedPrivateKey ed25519.PrivateKey, expectedC2PubKey [32]byte) {
	tkey, ok := key.(*ed25519Key)
	if !ok {
		t.Fatal("failed to cast key")
	}

	if bytes.Equal(tkey.SignerID, expectedSignerID) == false {
		t.Fatalf("expected signerID to be %v, got %v", expectedSignerID, tkey.SignerID)
	}

	if tkey.C2PublicKey != expectedC2PubKey {
		t.Fatalf("expected c2PublicKey to be %v, got %v", expectedC2PubKey, tkey.C2PublicKey)
	}

	if bytes.Equal(tkey.PrivateKey, expectedPrivateKey) == false {
		t.Fatalf("expected private key to be %v, got %v", expectedPrivateKey, tkey.PrivateKey)
	}
}

func getTestC2PublicKey(t *testing.T) [32]byte {
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 public key: %v", err)
	}
	var expectedC2PubKey [32]byte
	copy(expectedC2PubKey[:], pubKey[:32])

	return expectedC2PubKey
}

func TestNewRandomEd25519Key(t *testing.T) {
	expectedSignerID := e4crypto.HashIDAlias("test")
	expectedC2PubKey := getTestC2PublicKey(t)

	key, err := NewRandomEd25519Key(expectedSignerID, expectedC2PubKey)
	if err != nil {
		t.Fatalf("expected no error creating a key, got %v", err)
	}

	tkey, ok := key.(*ed25519Key)
	if !ok {
		t.Fatal("failed to cast key")
	}

	if bytes.Equal(tkey.SignerID, expectedSignerID) == false {
		t.Fatalf("expected signerID to be %v, got %v", expectedSignerID, tkey.SignerID)
	}

	if tkey.C2PublicKey != expectedC2PubKey {
		t.Fatalf("expected c2PublicKey to be %v, got %v", expectedC2PubKey, tkey.C2PublicKey)
	}

	if err := e4crypto.ValidEd25519PrivKey(tkey.PrivateKey); err != nil {
		t.Fatalf("expected a valid private key to be set: got error: %v", err)
	}
}

func TestProtectUnprotectMessage(t *testing.T) {
	clientID := e4crypto.HashIDAlias("test")
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 keys: %v", err)
	}

	k, err := NewEd25519Key(clientID, privKey, getTestC2PublicKey(t))
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	payload := []byte("some message")
	topicKey := e4crypto.RandomKey()

	protected, err := k.ProtectMessage(payload, topicKey)
	if err != nil {
		t.Fatalf("failed to protect message: %v", err)
	}

	_, err = k.UnprotectMessage(protected, topicKey)
	if err == nil {
		t.Fatal("expected unprotect to fail without the proper public key")
	}

	k.AddPubKey(string(clientID), pubKey)
	unprotected, err := k.UnprotectMessage(protected, topicKey)
	if err != nil {
		t.Fatalf("expected no error when unprotecting message, got %v", err)
	}

	if bytes.Equal(unprotected, payload) == false {
		t.Fatalf("expected unprotected message to be %v, got %v", unprotected, payload)
	}

	badTopicKey := e4crypto.RandomKey()
	_, err = k.UnprotectMessage(protected, badTopicKey)
	if err == nil {
		t.Fatal("expected unprotect to fail without the proper topic key")
	}
}
