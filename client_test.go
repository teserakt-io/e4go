// Copyright 2019 Teserakt AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e4

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/agl/ed25519/extra25519"
	miscreant "github.com/miscreant/miscreant.go"
	"golang.org/x/crypto/ed25519"

	e4crypto "github.com/teserakt-io/e4go/crypto"
	"github.com/teserakt-io/e4go/keys"
)

func TestNewClientSymKey(t *testing.T) {
	id := make([]byte, e4crypto.IDLen)
	k := make([]byte, e4crypto.KeyLen)

	rand.Read(id)
	rand.Read(k)

	c, err := NewClient(&SymIDAndKey{
		ID:  id,
		Key: k,
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatal(err)
	}

	c1, ok := c.(*client)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted client", c)
	}

	if c1.GetReceivingTopic() != TopicForID(id) {
		t.Fatalf("Invalid receiving topic: got %s, wanted %s", c1.ReceivingTopic, TopicForID(id))
	}

	if c1.IsReceivingTopic(TopicForID(id)) == false {
		t.Fatalf("Expected topic %s to be a receiving topic", TopicForID(id))
	}

	if c1.IsReceivingTopic("random/topic") == true {
		t.Fatalf("Expected topic random/topic to not be a receiving topic")
	}

	if !bytes.Equal(c1.ID, id) {
		t.Fatalf("Invalid ID: got %v, wanted %v", c1.ID, id)
	}

	if len(c1.TopicKeys) != 0 {
		t.Fatalf("Invalid topicKeys count: got %d, wanted 0", len(c1.TopicKeys))
	}

	if _, ok := c1.Key.(keys.SymKeyMaterial); !ok {
		t.Fatalf("Invalid key type: got %T, wanted SymKeyMaterial", c1.Key)
	}
}

func TestProtectUnprotectMessageSymKey(t *testing.T) {
	client, err := NewClient(&SymIDAndKey{
		Key: e4crypto.RandomKey(),
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	protectedConstLength := e4crypto.TagLen + e4crypto.TimestampLen
	testProtectUnprotectMessage(t, client, protectedConstLength)
}

func TestProtectUnprotectMessagePubKey(t *testing.T) {
	clientID := e4crypto.RandomID()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	client, err := NewClient(&PubIDAndKey{
		ID:       clientID,
		Key:      privateKey,
		C2PubKey: generateCurve25519PubKey(t),
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	err = client.setPubKey(publicKey, clientID)
	if err != nil {
		t.Fatalf("SetPubKey failed: %s", err)
	}

	protectedConstLength := e4crypto.TagLen + e4crypto.TimestampLen + e4crypto.IDLen + ed25519.SignatureSize
	testProtectUnprotectMessage(t, client, protectedConstLength)
}

func testProtectUnprotectMessage(t *testing.T, c Client, protectedConstLength int) {
	topic := "topic"
	err := c.setTopicKey(e4crypto.RandomKey(), e4crypto.HashTopic(topic))
	if err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	for i := 0; i < 256; i++ {
		rDelta := e4crypto.RandomDelta16()
		msgLen := 123 + int(rDelta)

		msg := make([]byte, msgLen)

		rand.Read(msg)

		protected, err := c.ProtectMessage(msg, topic)
		if err != nil {
			t.Fatalf("Protect failed: %s", err)
		}

		protectedlen := msgLen + protectedConstLength
		if len(protected) != protectedlen {
			t.Fatalf("Invalid protected message length: got %v, wanted %v", len(protected), protectedlen)
		}

		// happy case
		unprotected, err := c.Unprotect(protected, topic)
		if err != nil {
			t.Fatalf("Unprotect failed: %s", err)
		}
		if !bytes.Equal(unprotected, msg) {
			t.Fatalf("Invalid unprotected message: got %v, wanted %v", unprotected, msg)
		}

		// wrong ciphertext:
		invalidprotected := make([]byte, msgLen)
		copy(invalidprotected, protected)
		for i := range invalidprotected {
			invalidprotected[i] ^= 0x02
		}

		_, err = c.Unprotect(invalidprotected, topic)
		if err == nil {
			t.Fatalf("Ciphertext changed: decryption did not fail as expected")
		}

		// future timestamp and past timestamp
		timestamporig := protected[:e4crypto.TimestampLen]
		ts := time.Unix(int64(binary.LittleEndian.Uint64(timestamporig)), 0)
		tsf := ts.Add(1000000 * time.Second)
		tsp := ts.Add(-(e4crypto.MaxDelayDuration + 1))
		tsFuture := make([]byte, 8)
		tsPast := make([]byte, 8)
		binary.LittleEndian.PutUint64(tsFuture, uint64(tsf.Unix()))
		binary.LittleEndian.PutUint64(tsPast, uint64(tsp.Unix()))

		futureinvalidprotect := make([]byte, protectedlen)
		pastinvalidprotect := make([]byte, protectedlen)
		copy(futureinvalidprotect, tsFuture)
		copy(pastinvalidprotect, tsPast)
		copy(futureinvalidprotect[e4crypto.TimestampLen:], protected[e4crypto.TimestampLen:])
		copy(pastinvalidprotect[e4crypto.TimestampLen:], protected[e4crypto.TimestampLen:])

		_, err = c.Unprotect(futureinvalidprotect, topic)
		if err == nil {
			t.Fatalf("Timestamp in future: decryption did not fail as expected")
		}

		_, err = c.Unprotect(pastinvalidprotect, topic)
		if err == nil {
			t.Fatalf("Timestamp too old: decryption did not fail as expected")
		}
	}

	if _, err := c.ProtectMessage([]byte("payload"), "topic-not-existing"); err != ErrTopicKeyNotFound {
		t.Fatalf("Invalid error from ProtectMessage for an unknown topic, got %v, wanted %v", err, ErrTopicKeyNotFound)
	}

	if _, err := c.Unprotect([]byte("protected"), "topic-not-existing"); err != ErrTopicKeyNotFound {
		t.Fatalf("Invalid error from Unprotect for an unknown topic, got %v, wanted %v", err, ErrTopicKeyNotFound)
	}
}

func TestKeyTransition(t *testing.T) {
	clientID := e4crypto.HashIDAlias("client1")
	clientKey := e4crypto.RandomKey()
	topic := "topic"

	c, err := NewClient(&SymIDAndKey{
		ID:  clientID,
		Key: clientKey,
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	topicHash := e4crypto.HashTopic(topic)
	firstKey := e4crypto.RandomKey()
	secondKey := e4crypto.RandomKey()
	thirdKey := e4crypto.RandomKey()

	err = c.setTopicKey(firstKey, topicHash)
	if err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	msg := make([]byte, 16)
	rand.Read(msg)

	protected, err := c.ProtectMessage(msg, topic)
	if err != nil {
		t.Fatalf("Protect failed: %s", err)
	}

	// should succeed, first key is the only one
	if _, err := c.Unprotect(protected, topic); err != nil {
		t.Fatalf("Unprotect failed: %s", err)
	}

	if err := c.setTopicKey(secondKey, topicHash); err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	// should succeed, first key still available
	if _, err := c.Unprotect(protected, topic); err != nil {
		t.Fatalf("Unprotect failed: %s", err)
	}

	if err := c.setTopicKey(secondKey, topicHash); err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	// should succeed, sending second key again
	if _, err := c.Unprotect(protected, topic); err != nil {
		t.Fatalf("Unprotect failed: %s", err)
	}

	if err := c.setTopicKey(thirdKey, topicHash); err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	// should fail, first key no longer available
	if _, err := c.Unprotect(protected, topic); err != miscreant.ErrNotAuthentic {
		t.Fatalf("Unprotect return unexpected error type: got %v, wanted %v", err, miscreant.ErrNotAuthentic)
	}
}

func TestClientWriteRead(t *testing.T) {
	store := NewInMemoryStore(nil)
	gc, err := NewClient(&SymIDAndKey{
		Key: e4crypto.RandomKey(),
	}, store)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	c, ok := gc.(*client)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted client", gc)
	}

	err = c.setTopicKey(e4crypto.RandomKey(), e4crypto.HashTopic("topic"))
	if err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	err = c.setIDKey(e4crypto.RandomKey())
	if err != nil {
		t.Fatalf("SetIDKey failed: %s", err)
	}

	if len(c.TopicKeys) != 1 {
		t.Fatalf("Invalid number of topic keys: got %d, wanted 1", len(c.TopicKeys))
	}

	// state should be saved here
	err = c.resetTopics()
	if err != nil {
		t.Fatalf("ResetTopics failed: %s", err)
	}

	gcc, err := LoadClient(store)
	if err != nil {
		t.Fatalf("Failed to load client: %s", err)
	}
	if !reflect.DeepEqual(gcc, gc) {
		t.Fatalf("Invalid loaded client, got %#v, wanted %#v", gcc, gc)
	}
}

func TestProtectUnprotectCommandsPubKey(t *testing.T) {
	clientEdPk, clientEdSk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	c2PrivateCurveKey := e4crypto.RandomKey()
	c2PublicCurveKey, err := curve25519.X25519(c2PrivateCurveKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("Failed to generate curve25519 keys: %v", err)
	}

	command := []byte{0x05}
	sharedKey, err := curve25519.X25519(c2PrivateCurveKey, e4crypto.PublicEd25519KeyToCurve25519(clientEdPk))
	if err != nil {
		t.Fatalf("curve25519 X25519 failed: %v", err)
	}

	protected, err := e4crypto.ProtectSymKey(command, e4crypto.Sha3Sum256(sharedKey))
	if err != nil {
		t.Fatalf("ProtectSymKey failed: %v", err)
	}

	clientID := e4crypto.RandomID()
	gc, err := NewClient(&PubIDAndKey{
		ID:       clientID,
		Key:      clientEdSk,
		C2PubKey: c2PublicCurveKey,
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	c, ok := gc.(*client)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted client", gc)
	}

	res, err := gc.Unprotect(protected, c.ReceivingTopic)
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}

	if res != nil {
		t.Fatalf("Unprotect command returned non-nil value")
	}
}

func TestClientPubKeys(t *testing.T) {
	t.Run("pubKey client properly add / remove / reset pubKeys", func(t *testing.T) {
		config := &PubNameAndPassword{
			Name:     "testClient",
			Password: "passwordTestRandom",
			C2PubKey: generateCurve25519PubKey(t),
		}

		pubKey, err := config.PubKey()
		if err != nil {
			t.Fatalf("failed to get pubkey from config: %v", err)
		}

		store := NewInMemoryStore(nil)
		c, err := NewClient(config, store)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		if len(pubKey) == 0 {
			t.Fatal("Empty public key")
		}

		pks, err := c.getPubKeys()
		if err != nil {
			t.Fatalf("Failed to retrieve pubkeys: %v", err)
		}

		if len(pks) != 0 {
			t.Fatalf("Invalid pubkey count, got %d, wanted 0", len(pks))
		}

		id1 := e4crypto.RandomID()
		pubKey1, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("Failed to generate pubKey: %v", err)
		}

		if err := c.setPubKey(pubKey1, id1); err != nil {
			t.Fatalf("Failed to set pubkey: %v", err)
		}

		assertContainsPubKey(t, c, id1, pubKey1)
		assertSavedClientPubKeysEquals(t, store, c)

		id2 := e4crypto.RandomID()
		pubKey2, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("Failed to generate pubKey: %v", err)
		}

		if err := c.setPubKey(pubKey2, id2); err != nil {
			t.Fatalf("Failed to set pubkey: %v", err)
		}

		assertContainsPubKey(t, c, id1, pubKey1)
		assertContainsPubKey(t, c, id2, pubKey2)
		assertSavedClientPubKeysEquals(t, store, c)

		id3 := e4crypto.RandomID()
		if err := c.removePubKey(id3); err == nil {
			t.Fatal("Expected removal of pubKey with unknown ID to produce an error")
		}

		if err := c.removePubKey(id1); err != nil {
			t.Fatalf("Failed to remove a known pubKey: %v", err)
		}

		assertContainsPubKey(t, c, id2, pubKey2)
		assertSavedClientPubKeysEquals(t, store, c)

		pks, err = c.getPubKeys()
		if err != nil {
			t.Fatalf("Failed to retrieve pubkeys: %v", err)
		}

		if _, ok := pks[string(id1)]; ok {
			t.Fatal("Expected pubKey for id1 to have been removed")
		}

		if err := c.resetPubKeys(); err != nil {
			t.Fatalf("Failed to reset pubKeys: %v", err)
		}

		pks, err = c.getPubKeys()
		if err != nil {
			t.Fatalf("Failed to retrieve pubkeys: %v", err)
		}

		if len(pks) != 0 {
			t.Fatalf("Invalid public key count, got %d, wanted 0", len(pks))
		}

		assertSavedClientPubKeysEquals(t, store, c)
	})

	t.Run("pubKey client return errors on pubKey operations with invalid ids", func(t *testing.T) {
		config := &PubNameAndPassword{
			Name:     "testClient",
			Password: "passwordTestRandom",
			C2PubKey: generateCurve25519PubKey(t),
		}

		pubKey, err := config.PubKey()
		if err != nil {
			t.Fatalf("failed to get pubkey from config: %v", err)
		}

		c, err := NewClient(config, NewInMemoryStore(nil))
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		if len(pubKey) == 0 {
			t.Fatal("Empty public key")
		}

		pk, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("Failed to generate publicKey: %v", err)
		}

		if err := c.setPubKey(pk, []byte("bad id")); err == nil {
			t.Fatal("Expected an error when setting a pubkey with an invalid id")
		}

		if err := c.removePubKey([]byte("bad id")); err == nil {
			t.Fatal("Expected an error when setting a pubkey with an invalid id")
		}
	})

	t.Run("symClient must return unsupported operations on pubKey methods", func(t *testing.T) {
		symClient, err := NewClient(&SymNameAndPassword{
			Name:     "testClient",
			Password: "passwordTestRandom",
		}, NewInMemoryStore(nil))
		if err != nil {
			t.Fatalf("Failed to create symClient: %v", err)
		}

		if _, err := symClient.getPubKeys(); err != ErrUnsupportedOperation {
			t.Fatalf("Invalid error: got %v, wanted %v", err, ErrUnsupportedOperation)
		}

		if err := symClient.setPubKey([]byte{}, []byte{}); err != ErrUnsupportedOperation {
			t.Fatalf("Invalid error: got %v, wanted %v", err, ErrUnsupportedOperation)
		}

		if err := symClient.removePubKey([]byte{}); err != ErrUnsupportedOperation {
			t.Fatalf("Invalid error: got %v, wanted %v", err, ErrUnsupportedOperation)
		}

		if err := symClient.resetPubKeys(); err != ErrUnsupportedOperation {
			t.Fatalf("Invalid error: got %v, wanted %v", err, ErrUnsupportedOperation)
		}
	})
}

func TestClientTopics(t *testing.T) {
	t.Run("topic key operations properly update client state", func(t *testing.T) {
		symClient, err := NewClient(&SymNameAndPassword{
			Name:     "clientID",
			Password: "passwordTestRandom",
		}, NewInMemoryStore(nil))
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		tSymClient, ok := symClient.(*client)
		if !ok {
			t.Fatalf("Unexpected type: got %T, wanted client", symClient)
		}

		if c := len(tSymClient.TopicKeys); c != 0 {
			t.Fatalf("Invalid count of topic keys, got %d, wanted 0", c)
		}

		topicKey1 := e4crypto.RandomKey()
		topicHash1 := e4crypto.HashTopic("topic1")

		if err := tSymClient.setTopicKey(topicKey1, topicHash1); err != nil {
			t.Fatalf("Failed to set topic key: %v", err)
		}
		assertClientTopicKey(t, true, tSymClient, topicHash1, topicKey1)

		topicKey2 := e4crypto.RandomKey()
		topicHash2 := e4crypto.HashTopic("topic2")

		if err := tSymClient.setTopicKey(topicKey2, topicHash2); err != nil {
			t.Fatalf("Failed to set topic key: %v", err)
		}

		assertClientTopicKey(t, true, tSymClient, topicHash1, topicKey1)
		assertClientTopicKey(t, true, tSymClient, topicHash2, topicKey2)

		if err := tSymClient.removeTopic(topicHash1); err != nil {
			t.Fatalf("Failed to remove topic key: %v", err)
		}

		if c := len(tSymClient.TopicKeys); c != 1 {
			t.Fatalf("Invalid topic key count, got %d, wanted 1", c)
		}

		assertClientTopicKey(t, false, tSymClient, topicHash1, nil)
		assertClientTopicKey(t, true, tSymClient, topicHash2, topicKey2)

		if err := tSymClient.resetTopics(); err != nil {
			t.Fatalf("Failed to reset topics: %v", err)
		}
		if c := len(tSymClient.TopicKeys); c != 0 {
			t.Fatalf("Invalid topic key count, got %d, wanted 0", c)
		}
	})

	t.Run("topic key operations returns errors when invoked with bad topic hashes", func(t *testing.T) {
		symClient, err := NewClient(&SymNameAndPassword{
			Name:     "clientID",
			Password: "passwordTestRandom",
		}, NewInMemoryStore(nil))
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		topicKey := e4crypto.RandomKey()

		if err := symClient.setTopicKey(topicKey, []byte("bad hash")); err == nil {
			t.Fatal("Expected setTopicKey to fail with a bad topic hash")
		}

		if err := symClient.removeTopic([]byte("bad hash")); err == nil {
			t.Fatal("Expected RemoveTopic to fail with a bad topic hash")
		}
	})
}

func TestClientSetIDKey(t *testing.T) {
	clientID := e4crypto.HashIDAlias("client1")
	validKey := e4crypto.RandomKey()
	invalidKey := make([]byte, e4crypto.KeyLen)

	c, err := NewClient(&SymIDAndKey{
		ID:  clientID,
		Key: validKey,
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if err := c.setIDKey(invalidKey); err == nil {
		t.Fatal("Expected an error when calling setIDKey with an invalid key")
	}

}

func TestClientSetC2Key(t *testing.T) {
	c2PubKey, err := curve25519.X25519(e4crypto.RandomKey(), curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to generate public curve25519 key: %v", err)
	}

	c, err := NewClient(&SymIDAndKey{
		ID:  e4crypto.HashIDAlias("client1"),
		Key: e4crypto.RandomKey(),
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if err := c.setC2Key(c2PubKey); err != ErrUnsupportedOperation {
		t.Fatalf("Got error %v, wanted %v", err, ErrUnsupportedOperation)
	}

	_, edSk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 private key: %v", err)
	}

	c, err = NewClient(&PubIDAndKey{
		ID:       e4crypto.HashIDAlias("client1"),
		Key:      edSk,
		C2PubKey: c2PubKey,
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	newC2PubKey, err := curve25519.X25519(e4crypto.RandomKey(), curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to generate public curve25519 key: %v", err)
	}
	if err := c.setC2Key(newC2PubKey[1:]); err == nil {
		t.Fatalf("Got no error while setting an invald c2 public key")
	}

	if err := c.setC2Key(newC2PubKey); err != nil {
		t.Fatalf("Failed to set c2 public key: %v", err)
	}
}

func TestCommandsSymClient(t *testing.T) {
	clientID := e4crypto.HashIDAlias("client1")
	clientKey := e4crypto.RandomKey()
	topic := "topic1"

	c, err := NewClient(&SymIDAndKey{
		ID:  clientID,
		Key: clientKey,
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	receivingTopic := TopicForID(clientID)
	topicHash := e4crypto.HashTopic(topic)

	topicKey := e4crypto.RandomKey()
	setTopicCmd, err := CmdSetTopicKey(topicKey, topic)
	if err != nil {
		t.Fatalf("CmdSetTopicKey failed: %v", err)
	}

	protectedSetTopicCmd, err := e4crypto.ProtectSymKey(setTopicCmd, clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	badProtectedSetTopicCmd, err := e4crypto.ProtectSymKey(append(setTopicCmd, 0x01), clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedSetTopicCmd, receivingTopic); err == nil {
		t.Fatal("Expected an error with a bad setTopic Command length")
	}

	// Add the topic key
	d, err := c.Unprotect(protectedSetTopicCmd, receivingTopic)
	if err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("Expected no returned data, got %v", d)
	}

	assertClientTopicKey(t, true, c, topicHash, topicKey)

	removeTopicCmd := []byte{RemoveTopic}
	removeTopicCmd = append(removeTopicCmd, topicHash...)

	protectedRemoveTopicCmd, err := e4crypto.ProtectSymKey(removeTopicCmd, clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	badProtectedRemoveTopicCmd, err := e4crypto.ProtectSymKey(append(removeTopicCmd, 0x01), clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedRemoveTopicCmd, receivingTopic); err == nil {
		t.Fatal("Expected an error with a bad removeTopic Command length")
	}

	// Remove the topic key
	d, err = c.Unprotect(protectedRemoveTopicCmd, receivingTopic)
	if err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("Invalid unprotect command response, got %v, wanted nil", d)
	}

	assertClientTopicKey(t, false, c, topicHash, nil)

	// Add back the topic key
	d, err = c.Unprotect(protectedSetTopicCmd, receivingTopic)
	if err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("Invalid unprotect command response, got %v, wanted nil", d)
	}

	assertClientTopicKey(t, true, c, topicHash, topicKey)

	// Add a new topic key for the same topic, old one should still be available
	newTopicKey := e4crypto.RandomKey()
	setTopicCmd, err = CmdSetTopicKey(newTopicKey, topic)
	if err != nil {
		t.Fatalf("CmdSetTopicKey failed: %v", err)
	}

	protectedSetTopicCmd, err = e4crypto.ProtectSymKey(setTopicCmd, clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	d, err = c.Unprotect(protectedSetTopicCmd, receivingTopic)
	if err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("Invalid unprotect command response, got %v, wanted nil", d)
	}

	hashHash := e4crypto.HashTopic(string(topicHash))

	tc, ok := c.(*client)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted client", c)
	}

	k, ok := tc.TopicKeys[hex.EncodeToString(hashHash)]
	if !ok {
		t.Fatal("Previous key not found")
	}
	if g, w := len(k), e4crypto.KeyLen+e4crypto.TimestampLen; g != w {
		t.Fatalf("Invalid transition topic key lengths: got %d, wanted %d", g, w)
	}
	if !bytes.Equal(k[:e4crypto.KeyLen], topicKey) {
		t.Fatalf("Invalid topic key: got %v, wanted %v", k, topicKey)
	}

	// Reset topics
	resetTopicCmd := []byte{ResetTopics}
	protectedResetCmd, err := e4crypto.ProtectSymKey(resetTopicCmd, clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	badProtectedResetCmd, err := e4crypto.ProtectSymKey(append(resetTopicCmd, 0x01), clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedResetCmd, receivingTopic); err == nil {
		t.Fatal("Expected an error with a bad reset Command length")
	}

	d, err = c.Unprotect(protectedResetCmd, receivingTopic)
	if err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("Invalid unprotect command response, got %v, wanted nil", d)
	}

	assertClientTopicKey(t, false, c, topicHash, topicKey)

	// SetIDKey
	setIDKeyCmd := []byte{SetIDKey}

	newClientKey := e4crypto.RandomKey()
	setIDKeyCmd = append(setIDKeyCmd, newClientKey...)

	protectedSetIDKeyCmd, err := e4crypto.ProtectSymKey(setIDKeyCmd, clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	badProtectedSetIDKeyCmd, err := e4crypto.ProtectSymKey(append(setIDKeyCmd, 0x01), clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedSetIDKeyCmd, receivingTopic); err == nil {
		t.Fatal("Expected an error with a bad setIDKey Command length")
	}

	d, err = c.Unprotect(protectedSetIDKeyCmd, receivingTopic)
	if err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("Expected no returned data, got %v", d)
	}

	// Unprotecting again the same command must fail since the key have changed
	if _, err := c.Unprotect(protectedSetIDKeyCmd, receivingTopic); err == nil {
		t.Fatal("Expected an error with a command protected with old key")
	}

	setPubKeyCmd := []byte{SetPubKey}
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate pubkey: %v", err)
	}
	setPubKeyCmd = append(setPubKeyCmd, pubKey...)

	pubKeyID := e4crypto.RandomID()
	setPubKeyCmd = append(setPubKeyCmd, pubKeyID...)
	protectedSetPubKeyCmd, err := e4crypto.ProtectSymKey(setPubKeyCmd, newClientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	badProtectedSetPubKeyCmd, err := e4crypto.ProtectSymKey(append(setPubKeyCmd, 0x01), newClientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedSetPubKeyCmd, receivingTopic); err == nil {
		t.Fatal("Expected an error with a bad setPubKey Command length")
	}

	_, err = c.Unprotect(protectedSetPubKeyCmd, receivingTopic)
	if err != ErrUnsupportedOperation {
		t.Fatalf("Invalid error when unprotecting command: got %v, wanted %v", err, ErrUnsupportedOperation)
	}

	// RemovePubKey
	removePubKeyCmd := []byte{RemovePubKey}
	removePubKeyCmd = append(removePubKeyCmd, pubKeyID...)

	protectedRemovePubKeyCmd, err := e4crypto.ProtectSymKey(removePubKeyCmd, newClientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	badProtectedRemovePubKeyCmd, err := e4crypto.ProtectSymKey(append(removePubKeyCmd, 0x01), newClientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedRemovePubKeyCmd, receivingTopic); err == nil {
		t.Fatal("Expected an error with a bad removePubKey Command length")
	}

	_, err = c.Unprotect(protectedRemovePubKeyCmd, receivingTopic)
	if err != ErrUnsupportedOperation {
		t.Fatalf("Invalid error when unprotecting command: got %v, wanted %v", err, ErrUnsupportedOperation)
	}

	// ResetPubKeys
	resetPubKeyCmd := []byte{ResetPubKeys}

	protectedResetPubKeyCmd, err := e4crypto.ProtectSymKey(resetPubKeyCmd, newClientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	badProtectedResetPubKeyCmd, err := e4crypto.ProtectSymKey(append(resetPubKeyCmd, 0x01), newClientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedResetPubKeyCmd, receivingTopic); err == nil {
		t.Fatal("Expected an error with a bad resetPubKey Command length")
	}

	_, err = c.Unprotect(protectedResetPubKeyCmd, receivingTopic)
	if err != ErrUnsupportedOperation {
		t.Fatalf("Invalid error when unprotecting command: got %v, wanted %v", err, ErrUnsupportedOperation)
	}

	setC2KeyCmd := []byte{SetC2Key}
	badProtectedSetC2KeyCmd, err := e4crypto.ProtectSymKey(append(setC2KeyCmd, 0x01), newClientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedSetC2KeyCmd, receivingTopic); err == nil {
		t.Fatal("Expected an error with a bad setC2Key Command length")
	}

	pubkey, err := curve25519.X25519(e4crypto.RandomKey(), curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to generate pubkey: %v", err)
	}
	protectedSetC2KeyCmd, err := e4crypto.ProtectSymKey(append(setC2KeyCmd, pubkey...), newClientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	_, err = c.Unprotect(protectedSetC2KeyCmd, receivingTopic)
	if err != ErrUnsupportedOperation {
		t.Fatalf("Invalid error when unprotecting command: got %v, wanted %v", err, ErrUnsupportedOperation)
	}

	// Unknown command
	unknownCmd := []byte{0xFF}
	protectedUnknownCmd, err := e4crypto.ProtectSymKey(unknownCmd, newClientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	_, err = c.Unprotect(protectedUnknownCmd, receivingTopic)
	if err != ErrInvalidCommand {
		t.Fatalf("Invalid error when unprotecting command: got %v, wanted %v", err, ErrInvalidCommand)
	}
}

func assertClientTopicKey(t *testing.T, exists bool, c Client, topicHash []byte, topicKey []byte) {
	tc, ok := c.(*client)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted client", c)
	}

	k, ok := tc.TopicKeys[hex.EncodeToString(topicHash)]
	if exists && !ok {
		t.Fatalf("Expected client to have topic %s key", hex.EncodeToString(topicHash))
	} else if !exists && ok {
		t.Fatalf("Expected client to not have topic %s key", hex.EncodeToString(topicHash))
	}

	if exists {
		if !bytes.Equal(k, topicKey) {
			t.Fatalf("Invalid topic key: got %v, wanted %v", k, topicKey)
		}
	}
}

func assertContainsPubKey(t *testing.T, c Client, id []byte, key []byte) {
	pks, err := c.getPubKeys()
	if err != nil {
		t.Fatalf("Failed to retrieve pubkeys: %v", err)
	}

	pk, ok := pks[hex.EncodeToString(id)]
	if !ok {
		t.Fatal("Expected pubkey to be set on client")
	}
	if !bytes.Equal(pk, key) {
		t.Fatalf("Invalid pubKey: got %v, wanted %v", pk, key)
	}
}

func assertSavedClientPubKeysEquals(t *testing.T, store io.ReadWriteSeeker, c Client) {
	savedClient, err := LoadClient(store)
	if err != nil {
		t.Fatalf("Failed to load client: %v", err)
	}

	savedPk, err := savedClient.getPubKeys()
	if err != nil {
		t.Fatalf("Failed to get savedClient pubKeys: %v", err)
	}
	cPk, err := c.getPubKeys()
	if err != nil {
		t.Fatalf("Failed to get client pubKeys: %v", err)
	}
	if !reflect.DeepEqual(savedPk, cPk) {
		t.Fatalf("Invalid saved client pubKeys: got %#v, wanted %#v", savedPk, cPk)
	}
}

func generateCurve25519PubKey(t *testing.T) []byte {
	var c2PubKey [e4crypto.Curve25519PubKeyLen]byte

	c2EdPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate c2 public key: %v", err)
	}

	var c2EdPk [ed25519.PublicKeySize]byte
	copy(c2EdPk[:], c2EdPubKey)

	extra25519.PublicKeyToCurve25519(&c2PubKey, &c2EdPk)

	return c2PubKey[:]
}
