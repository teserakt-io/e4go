package e4common

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestNewClientSymKey(t *testing.T) {

	id := make([]byte, IDLen)
	k := make([]byte, KeyLen)

	rand.Read(id)
	rand.Read(k)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	path := "./test/data/clienttestnew"
	protocol := SymKey

	c1, err := NewClient(id, k, sk, path, protocol)

	if err != nil {
		t.Fatal(err)
	}

	if c1.ReceivingTopic != TopicForID(id) {
		t.Fatalf("receiving topic does not match")
	}

	if c1.Ed25519Key != nil {
		t.Fatalf("ed25519 key should be nil in a SymKey client")
	}

	if string(c1.ID) != string(id) {
		t.Fatalf("ID does not match")
	}

	if string(c1.SymKey) != string(k) {
		t.Fatalf("symmetric key does not match")
	}

	if c1.FilePath != path {
		t.Fatalf("file  path does not match")
	}

	if len(c1.Pubkeys) != 0 {
		t.Fatalf("pubkeys initialized to non-empty array")
	}

	if len(c1.Topickeys) != 0 {
		t.Fatalf("topickeys initialized to non-empty array")
	}
}

func TestProtectUnprotectMessageSymKey(t *testing.T) {
	testProtectUnprotectMessage(t, SymKey)
}

func TestProtectUnprotectMessagePubKey(t *testing.T) {
	testProtectUnprotectMessage(t, PubKey)
}

func testProtectUnprotectMessage(t *testing.T, protocolVersion Protocol) {

	c, err := NewClient(nil, nil, nil, "./test/data/clienttestprotect", protocolVersion)

	if err != nil {
		t.Fatalf("NewClient failed: %s", err)
	}

	topic := "topic"

	err = c.SetTopicKey(RandomKey(), HashTopic(topic))

	if err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	if protocolVersion == PubKey {
		pk := c.Ed25519Key[32:]
		err = c.SetPubKey(pk, c.ID)

		if err != nil {
			t.Fatalf("SetPubKey failed: %s", err)
		}
	}

	for i := 0; i < 2048; i++ {
		rdelta := getRDelta()
		msgLen := 123 + int(rdelta)

		msg := make([]byte, msgLen)

		rand.Read(msg)

		protected, err := c.ProtectMessage(msg, topic)
		if err != nil {
			t.Fatalf("protect failed: %s", err)
		}

		protectedlen := msgLen + TagLen + TimestampLen
		if protocolVersion == PubKey {
			protectedlen += IDLen + ed25519.SignatureSize
		}

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

	protocol := SymKey

	c, err := NewClient(nil, nil, nil, filePath, protocol)

	if err != nil {
		t.Fatalf("NewClient failed: %s", err)
	}

	err = c.SetTopicKey(RandomKey(), HashTopic("topic"))

	if err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	err = c.SetIDKey(RandomKey())

	if err != nil {
		t.Fatalf("SetIDKey failed: %s", err)
	}

	if len(c.Topickeys) != 1 {
		t.Fatalf("invalid number of topic keys: %d vs 1 expected", len(c.Topickeys))
	}

	// state should be saved here
	err = c.ResetTopics()

	if err != nil {
		t.Fatalf("save failed: %s", err)
	}

	cc, err := LoadClient(filePath)
	if err != nil {
		t.Fatalf("client loading failed: %s", err)
	}

	if string(cc.ID) != string(c.ID) {
		t.Fatal("id doesnt match")
	}
	if string(cc.SymKey) != string(c.SymKey) {
		t.Fatal("key doesnt match")
	}
	if cc.FilePath != c.FilePath {
		t.Fatal("filepath doesnt match")
	}
	// check that topickeys on disk was changed after ResetTopics
	if len(cc.Topickeys) != 0 {
		t.Fatalf("invalid number of topic keys: %d vs 0 expected", len(cc.Topickeys))
	}
}

func TestCommands(t *testing.T) {

}
