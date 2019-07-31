package e4common

import (
	"testing"
)

func TestClientNew(t *testing.T) {

	id := make([]byte, IDLen)
	k := make([]byte, KeyLen)
	path := "./test/data/clienttestnew"
	protocol := SymKey

	c1, err := NewClient(id, k, k, path, protocol)

	if err != nil {
		t.Fatal(err)
	}

	if c1.ReceivingTopic != TopicForID(id) {
		t.Fatalf("receiving topic does not match")
	}

	if c1.Ed25519Key != nil {
		t.Fatalf("ed25519 key should be nil in a SymKey client")
	}

}

// OLD TESTS

func TestClientNewPretty(t *testing.T) {

	c1 := NewClientPretty("someid", "somepwd", "./test/data/clienttestnew")

	c2 := NewClientPretty("someid", "somepwd", "./test/data/clienttestnew")

	if string(c1.ID) != string(c2.ID) {
		t.Fatalf("ID of new clients don't match")
	}

	if string(c1.Key) != string(c2.Key) {
		t.Fatalf("keys of new clients don't match")
	}

	if c1.ReceivingTopic != c2.ReceivingTopic {
		t.Fatalf("receiving topics of new clients don't match")
	}
}

func TestClientProtectUnprotect(t *testing.T) {

	c := NewClient(nil, nil, "./test/data/clienttestprotect")

	payload := []byte("cleartext")
	topic := "topic"

	err := c.SetTopicKey(RandomKey(), HashTopic(topic))

	if err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	protected, err := c.Protect(payload, topic)

	if err != nil {
		t.Fatalf("Protect failed: %s", err)
	}

	unprotected, err := c.Unprotect(protected, topic)

	if err != nil {
		t.Fatalf("Protect failed: %s", err)
	}

	if string(payload) != string(unprotected) {
		t.Fatalf("decrypted payload doesn't match")
	}
}

func TestClientWriteRead(t *testing.T) {
	filePath := "./test/data/clienttestwriteread"

	c := NewClient(nil, nil, filePath)

	err := c.SetTopicKey(RandomKey(), HashTopic("topic"))

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
	if string(cc.Key) != string(c.Key) {
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

// NEW TESTS

func TestProtectUnprotectMessageSymKey(t *testing.T) {

}

func TestProtectUnprotectMessagePubKey(t *testing.T) {

}

func TestProtectUnprotectCommandsSymKey(t *testing.T) {

}

func TestProtectUnprotectCommandsPubKey(t *testing.T) {

}

func TestCommands(t *testing.T) {

}
