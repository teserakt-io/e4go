package e4common

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"reflect"
	"testing"

	"gitlab.com/teserakt/e4common/keys"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/ed25519"

	e4crypto "gitlab.com/teserakt/e4common/crypto"
)

func TestNewClientSymKey(t *testing.T) {
	id := make([]byte, e4crypto.IDLen)
	k := make([]byte, e4crypto.KeyLen)

	rand.Read(id)
	rand.Read(k)

	path := "./test/data/clienttestnew"

	c, err := NewSymKeyClient(id, k, path)
	if err != nil {
		t.Fatal(err)
	}

	c1, ok := c.(*client)
	if !ok {
		t.Fatal("failed to cast Client interface to client implementation")
	}

	if c1.ReceivingTopic != topicForID(id) {
		t.Fatalf("receiving topic does not match")
	}

	if string(c1.ID) != string(id) {
		t.Fatalf("ID does not match")
	}

	if c1.FilePath != path {
		t.Fatalf("file  path does not match")
	}

	if len(c1.TopicKeys) != 0 {
		t.Fatalf("topickeys initialized to non-empty array")
	}

	if _, ok := c1.Key.(keys.SymKey); !ok {
		t.Fatalf("expected client to hold a SymKey, got %T", c1.Key)
	}
}

func TestProtectUnprotectMessageSymKey(t *testing.T) {
	client, err := NewSymKeyClient(nil, e4crypto.RandomKey(), "./test/data/clienttestprotectSymKey")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	protectedConstLength := e4crypto.TagLen + e4crypto.TimestampLen
	testProtectUnprotectMessage(t, client, protectedConstLength)
}

func TestProtectUnprotectMessagePubKey(t *testing.T) {
	clientID := e4crypto.RandomID()
	var c2Key [32]byte

	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	client, err := NewPubKeyClient(clientID, privateKey, "./test/data/clienttestprotectPubKey", c2Key)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	pk := privateKey[32:]
	err = client.SetPubKey(pk, clientID)
	if err != nil {
		t.Fatalf("SetPubKey failed: %s", err)
	}

	protectedConstLength := e4crypto.TagLen + e4crypto.TimestampLen + e4crypto.IDLen + ed25519.SignatureSize
	testProtectUnprotectMessage(t, client, protectedConstLength)
}

func testProtectUnprotectMessage(t *testing.T, c Client, protectedConstLength int) {
	topic := "topic"
	err := c.SetTopicKey(e4crypto.RandomKey(), e4crypto.HashTopic(topic))
	if err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	for i := 0; i < 2048; i++ {
		rdelta := e4crypto.GetRDelta()
		msgLen := 123 + int(rdelta)

		msg := make([]byte, msgLen)

		rand.Read(msg)

		protected, err := c.ProtectMessage(msg, topic)
		if err != nil {
			t.Fatalf("protect failed: %s", err)
		}

		protectedlen := msgLen + protectedConstLength
		if len(protected) != protectedlen {
			t.Fatalf("protected message has invalid length: %v instead of %v", len(protected), protectedlen)
		}

		// happy case.
		unprotected, err := c.Unprotect(protected, topic)
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

		_, err = c.Unprotect(invalidprotected, topic)
		if err == nil {
			t.Fatalf("ciphertext changed: decryption did not fail as expected")
		}

		// future timestamp and past timestamp
		timestamporig := protected[:e4crypto.TimestampLen]
		ts := binary.LittleEndian.Uint64(timestamporig)
		tsf := ts + 1000000
		tsp := ts - (e4crypto.MaxSecondsDelay + 1)
		tsfuture := make([]byte, 8)
		tspast := make([]byte, 8)
		binary.LittleEndian.PutUint64(tsfuture, tsf)
		binary.LittleEndian.PutUint64(tspast, tsp)

		futureinvalidprotect := make([]byte, protectedlen)
		pastinvalidprotect := make([]byte, protectedlen)
		copy(futureinvalidprotect, tsfuture)
		copy(pastinvalidprotect, tspast)
		copy(futureinvalidprotect[e4crypto.TimestampLen:], protected[e4crypto.TimestampLen:])
		copy(pastinvalidprotect[e4crypto.TimestampLen:], protected[e4crypto.TimestampLen:])

		_, err = c.Unprotect(futureinvalidprotect, topic)
		if err == nil {
			t.Fatalf("timestamp in future: decryption did not fail as expected")
		}

		_, err = c.Unprotect(pastinvalidprotect, topic)
		if err == nil {
			t.Fatalf("timestamp too old: decryption did not fail as expected")
		}

	}
}

func TestClientWriteRead(t *testing.T) {
	filePath := "./test/data/clienttestwriteread"

	gc, err := NewSymKeyClient(nil, e4crypto.RandomKey(), filePath)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	c, ok := gc.(*client)
	if !ok {
		t.Fatal("failed to cast Client interface to client implementation")
	}

	err = c.SetTopicKey(e4crypto.RandomKey(), e4crypto.HashTopic("topic"))
	if err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	err = c.SetIDKey(e4crypto.RandomKey())
	if err != nil {
		t.Fatalf("SetIDKey failed: %s", err)
	}

	if len(c.TopicKeys) != 1 {
		t.Fatalf("invalid number of topic keys: %d vs 1 expected", len(c.TopicKeys))
	}

	// state should be saved here
	err = c.ResetTopics()
	if err != nil {
		t.Fatalf("save failed: %s", err)
	}

	gcc, err := LoadClient(filePath)
	if err != nil {
		t.Fatalf("client loading failed: %s", err)
	}

	if reflect.DeepEqual(gcc, gc) == false {
		t.Fatalf("expected client to be %#v, got %#v", gc, gcc)
	}
}

func TestCommands(t *testing.T) {

	// TODO
}

func TestProtectUnprotectCommandsPubKey(t *testing.T) {
	_, clientEdSk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}
	_, c2EdSk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	var cedpk [32]byte
	var cpk [32]byte
	copy(cedpk[:], clientEdSk[32:])
	extra25519.PublicKeyToCurve25519(&cpk, &cedpk)

	var c2edsk [64]byte
	var c2edpk [32]byte
	var c2pk [32]byte
	var c2sk [32]byte
	copy(c2edsk[:], c2EdSk)
	copy(c2edpk[:], c2EdSk[32:])
	extra25519.PublicKeyToCurve25519(&c2pk, &c2edpk)
	extra25519.PrivateKeyToCurve25519(&c2sk, &c2edsk)

	command := []byte{0x05}
	protected, err := e4crypto.ProtectCommandPubKey(command, &cpk, &c2sk)

	if err != nil {
		t.Fatalf("ProtectCommandPubKey failed: %v", err)
	}

	clientID := e4crypto.RandomID()
	gc, err := NewPubKeyClient(clientID, clientEdSk, "./test/data/clienttestcommand", c2pk)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	c, ok := gc.(*client)
	if !ok {
		t.Fatal("failed to cast Client interface to client implementation")
	}

	res, err := gc.Unprotect(protected, c.ReceivingTopic)
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}

	if res != nil {
		t.Fatalf("Unprotect returned non-nil value")
	}
}
