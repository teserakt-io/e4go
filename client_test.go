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

	miscreant "github.com/miscreant/miscreant.go"
	"github.com/teserakt-io/golang-ed25519/extra25519"
	"golang.org/x/crypto/ed25519"

	e4crypto "github.com/teserakt-io/e4go/crypto"
	"github.com/teserakt-io/e4go/keys"
)

func TestNewClientSymKey(t *testing.T) {
	id := make([]byte, e4crypto.IDLen)
	k := make([]byte, e4crypto.KeyLen)

	rand.Read(id)
	rand.Read(k)

	symClient, err := NewClient(&SymIDAndKey{
		ID:  id,
		Key: k,
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatal(err)
	}

	typedSymClient, ok := symClient.(*client)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted client", symClient)
	}

	if typedSymClient.GetReceivingTopic() != TopicForID(id) {
		t.Fatalf("Invalid receiving topic: got %s, wanted %s", typedSymClient.ReceivingTopic, TopicForID(id))
	}

	if typedSymClient.IsReceivingTopic(TopicForID(id)) == false {
		t.Fatalf("Expected topic %s to be a receiving topic", TopicForID(id))
	}

	if typedSymClient.IsReceivingTopic("random/topic") == true {
		t.Fatalf("Expected topic random/topic to not be a receiving topic")
	}

	if !bytes.Equal(typedSymClient.ID, id) {
		t.Fatalf("Invalid ID: got %v, wanted %v", typedSymClient.ID, id)
	}

	if len(typedSymClient.TopicKeys) != 0 {
		t.Fatalf("Invalid topicKeys count: got %d, wanted 0", len(typedSymClient.TopicKeys))
	}

	if _, ok := typedSymClient.Key.(keys.SymKeyMaterial); !ok {
		t.Fatalf("Invalid key type: got %T, wanted SymKeyMaterial", typedSymClient.Key)
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

	client, err := NewClient(&SymIDAndKey{
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

	err = client.setTopicKey(firstKey, topicHash)
	if err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	msg := make([]byte, 16)
	if _, err := rand.Read(msg); err != nil {
		t.Fatalf("failed to read random bytes: %v", err)
	}

	protected, err := client.ProtectMessage(msg, topic)
	if err != nil {
		t.Fatalf("Protect failed: %s", err)
	}

	// should succeed, first key is the only one
	if _, err := client.Unprotect(protected, topic); err != nil {
		t.Fatalf("Unprotect failed: %s", err)
	}

	if err := client.setTopicKey(secondKey, topicHash); err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	// should succeed, first key still available
	if _, err := client.Unprotect(protected, topic); err != nil {
		t.Fatalf("Unprotect failed: %s", err)
	}

	if err := client.setTopicKey(secondKey, topicHash); err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	// should succeed, sending second key again
	if _, err := client.Unprotect(protected, topic); err != nil {
		t.Fatalf("Unprotect failed: %s", err)
	}

	if err := client.setTopicKey(thirdKey, topicHash); err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	// should fail, first key no longer available
	if _, err := client.Unprotect(protected, topic); err != miscreant.ErrNotAuthentic {
		t.Fatalf("Unprotect return unexpected error type: got %v, wanted %v", err, miscreant.ErrNotAuthentic)
	}
}

func TestClientWriteRead(t *testing.T) {
	store := NewInMemoryStore(nil)
	symClient, err := NewClient(&SymIDAndKey{
		Key: e4crypto.RandomKey(),
	}, store)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	typedClient, ok := symClient.(*client)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted client", symClient)
	}

	err = typedClient.setTopicKey(e4crypto.RandomKey(), e4crypto.HashTopic("topic"))
	if err != nil {
		t.Fatalf("SetTopicKey failed: %s", err)
	}

	err = typedClient.setIDKey(e4crypto.RandomKey())
	if err != nil {
		t.Fatalf("SetIDKey failed: %s", err)
	}

	if len(typedClient.TopicKeys) != 1 {
		t.Fatalf("Invalid number of topic keys: got %d, wanted 1", len(typedClient.TopicKeys))
	}

	// state should be saved here
	err = typedClient.resetTopics()
	if err != nil {
		t.Fatalf("ResetTopics failed: %s", err)
	}

	loadedClient, err := LoadClient(store)
	if err != nil {
		t.Fatalf("Failed to load client: %s", err)
	}
	if !reflect.DeepEqual(loadedClient, symClient) {
		t.Fatalf("Invalid loaded client, got %#v, wanted %#v", loadedClient, symClient)
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
	sharedPoint, err := curve25519.X25519(c2PrivateCurveKey, e4crypto.PublicEd25519KeyToCurve25519(clientEdPk))
	if err != nil {
		t.Fatalf("curve25519 X25519 failed: %v", err)
	}

	protected, err := e4crypto.ProtectSymKey(command, e4crypto.Sha3Sum256(sharedPoint))
	if err != nil {
		t.Fatalf("ProtectSymKey failed: %v", err)
	}

	clientID := e4crypto.RandomID()
	pubClient, err := NewClient(&PubIDAndKey{
		ID:       clientID,
		Key:      clientEdSk,
		C2PubKey: c2PublicCurveKey,
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	res, err := pubClient.Unprotect(protected, pubClient.GetReceivingTopic())
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}

	if res != nil {
		t.Fatalf("Unprotect command returned non-nil value")
	}
}

func TestClientPubKeys_addRemoveResetPubKeys(t *testing.T) {
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
	e4Client, err := NewClient(config, store)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if len(pubKey) == 0 {
		t.Fatal("Empty public key")
	}

	pks, err := e4Client.getPubKeys()
	if err != nil {
		t.Fatalf("Failed to retrieve pubkeys: %v", err)
	}

	if len(pks) != 0 {
		t.Fatalf("Invalid pubkey count, got %d, wanted 0", len(pks))
	}

	name1 := "client1"
	id1 := e4crypto.HashIDAlias(name1)
	pubKey1, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate pubKey: %v", err)
	}

	if err := e4Client.setPubKey(pubKey1, id1); err != nil {
		t.Fatalf("Failed to set pubkey: %v", err)
	}

	assertClientPubKey(t, true, e4Client, name1, pubKey1)
	assertSavedClientPubKeysEquals(t, store, e4Client)

	name2 := "client2"
	id2 := e4crypto.HashIDAlias(name2)
	pubKey2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate pubKey: %v", err)
	}

	if err := e4Client.setPubKey(pubKey2, id2); err != nil {
		t.Fatalf("Failed to set pubkey: %v", err)
	}

	assertClientPubKey(t, true, e4Client, name1, pubKey1)
	assertClientPubKey(t, true, e4Client, name2, pubKey2)
	assertSavedClientPubKeysEquals(t, store, e4Client)

	name3 := "client3"
	id3 := e4crypto.HashIDAlias(name3)
	if err := e4Client.removePubKey(id3); err == nil {
		t.Fatal("Expected removal of pubKey with unknown ID to produce an error")
	}

	if err := e4Client.removePubKey(id1); err != nil {
		t.Fatalf("Failed to remove a known pubKey: %v", err)
	}

	assertClientPubKey(t, true, e4Client, name2, pubKey2)
	assertSavedClientPubKeysEquals(t, store, e4Client)

	pks, err = e4Client.getPubKeys()
	if err != nil {
		t.Fatalf("Failed to retrieve pubkeys: %v", err)
	}

	if _, ok := pks[string(id1)]; ok {
		t.Fatal("Expected pubKey for id1 to have been removed")
	}

	if err := e4Client.resetPubKeys(); err != nil {
		t.Fatalf("Failed to reset pubKeys: %v", err)
	}

	pks, err = e4Client.getPubKeys()
	if err != nil {
		t.Fatalf("Failed to retrieve pubkeys: %v", err)
	}

	if len(pks) != 0 {
		t.Fatalf("Invalid public key count, got %d, wanted 0", len(pks))
	}

	assertSavedClientPubKeysEquals(t, store, e4Client)
}

func TestClientPubKeys_addRemoveWithInvalidIDs(t *testing.T) {
	config := &PubNameAndPassword{
		Name:     "testClient",
		Password: "passwordTestRandom",
		C2PubKey: generateCurve25519PubKey(t),
	}

	pubKey, err := config.PubKey()
	if err != nil {
		t.Fatalf("failed to get pubkey from config: %v", err)
	}

	pubClient, err := NewClient(config, NewInMemoryStore(nil))
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

	if err := pubClient.setPubKey(pk, []byte("bad id")); err == nil {
		t.Fatal("Expected an error when setting a pubkey with an invalid id")
	}

	if err := pubClient.removePubKey([]byte("bad id")); err == nil {
		t.Fatal("Expected an error when setting a pubkey with an invalid id")
	}
}

func TestSymClient_pubKeyMethods(t *testing.T) {
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
}

func TestClientTopics_setRemoveResetTopicKeys(t *testing.T) {
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
	topic1 := "topic1"
	topicHash1 := e4crypto.HashTopic(topic1)

	if err := tSymClient.setTopicKey(topicKey1, topicHash1); err != nil {
		t.Fatalf("Failed to set topic key: %v", err)
	}
	assertClientTopicKey(t, true, tSymClient, topic1, topicKey1)

	topicKey2 := e4crypto.RandomKey()
	topic2 := "topic2"
	topicHash2 := e4crypto.HashTopic(topic2)

	if err := tSymClient.setTopicKey(topicKey2, topicHash2); err != nil {
		t.Fatalf("Failed to set topic key: %v", err)
	}

	assertClientTopicKey(t, true, tSymClient, topic1, topicKey1)
	assertClientTopicKey(t, true, tSymClient, topic2, topicKey2)

	if err := tSymClient.removeTopic(topicHash1); err != nil {
		t.Fatalf("Failed to remove topic key: %v", err)
	}

	if c := len(tSymClient.TopicKeys); c != 1 {
		t.Fatalf("Invalid topic key count, got %d, wanted 1", c)
	}

	assertClientTopicKey(t, false, tSymClient, topic1, topicKey1)
	assertClientTopicKey(t, true, tSymClient, topic2, topicKey2)

	if err := tSymClient.resetTopics(); err != nil {
		t.Fatalf("Failed to reset topics: %v", err)
	}
	if c := len(tSymClient.TopicKeys); c != 0 {
		t.Fatalf("Invalid topic key count, got %d, wanted 0", c)
	}
}

func TestClientTopics_setRemoveInvalidTopics(t *testing.T) {
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
}

func TestSymClient_setIDKey(t *testing.T) {
	symClient, err := NewClient(&SymIDAndKey{
		ID:  e4crypto.HashIDAlias("client1"),
		Key: e4crypto.RandomKey(),
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	validSymKey := e4crypto.RandomKey()
	if err := symClient.setIDKey(validSymKey); err != nil {
		t.Fatalf("failed to set valid symkey: %v", err)
	}
}

func TestSymClient_invalidSetIDKey(t *testing.T) {
	_, edSk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key")
	}

	invalidKeys := [][]byte{
		make([]byte, e4crypto.KeyLen),
		e4crypto.RandomKey()[:e4crypto.KeyLen-1],
		edSk,
	}

	symClient, err := NewClient(&SymIDAndKey{
		ID:  e4crypto.HashIDAlias("client1"),
		Key: e4crypto.RandomKey(),
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	for _, key := range invalidKeys {
		if err := symClient.setIDKey(key); err == nil {
			t.Fatal("an error was expected when setting an invalid symkey")
		}
	}
}

func TestPubClient_setIDKey(t *testing.T) {
	_, edSk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key")
	}

	c2PubKey := make([]byte, e4crypto.Curve25519PubKeyLen)
	if _, err = rand.Read(c2PubKey); err != nil {
		t.Fatalf("failed to generate c2 pubkey: %v", err)
	}

	pubClient, err := NewClient(&PubIDAndKey{
		ID:       e4crypto.HashIDAlias("client1"),
		Key:      edSk,
		C2PubKey: c2PubKey,
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	_, validEdSk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	if err := pubClient.setIDKey(validEdSk); err != nil {
		t.Fatalf("failed to set valid ed25519 key: %v", err)
	}
}

func TestPubClient_invalidSetIDKey(t *testing.T) {
	_, validEdSk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	c2PubKey := make([]byte, e4crypto.Curve25519PubKeyLen)
	if _, err = rand.Read(c2PubKey); err != nil {
		t.Fatalf("failed to generate c2 pubkey: %v", err)
	}

	testCases := []struct {
		name string
		key  []byte
	}{
		{"all zeros", make([]byte, ed25519.PrivateKeySize)},
		{"ed25519.PrivateKeySize-1", validEdSk[:ed25519.PrivateKeySize-1]},
		{"32 bits key", e4crypto.RandomKey()},
	}

	pubClient, err := NewClient(&PubIDAndKey{
		ID:       e4crypto.HashIDAlias("client1"),
		Key:      validEdSk,
		C2PubKey: c2PubKey,
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := pubClient.setIDKey(testCase.key); err == nil {
				t.Fatal("an error was expected when setting an invalid ed25519 private key")
			}
		})
	}
}

func TestClient_setC2Key(t *testing.T) {
	c2PubKey, err := curve25519.X25519(e4crypto.RandomKey(), curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to generate public curve25519 key: %v", err)
	}

	symClient, err := NewClient(&SymIDAndKey{
		ID:  e4crypto.HashIDAlias("client1"),
		Key: e4crypto.RandomKey(),
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if err := symClient.setC2Key(c2PubKey); err != ErrUnsupportedOperation {
		t.Fatalf("Got error %v, wanted %v", err, ErrUnsupportedOperation)
	}

	_, edSk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 private key: %v", err)
	}

	pubClient, err := NewClient(&PubIDAndKey{
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
	if err := pubClient.setC2Key(newC2PubKey[1:]); err == nil {
		t.Fatalf("Got no error while setting an invald c2 public key")
	}

	if err := pubClient.setC2Key(newC2PubKey); err != nil {
		t.Fatalf("Failed to set c2 public key: %v", err)
	}
}

func setupForSymClientUnprotectTests(t *testing.T) (Client, []byte) {
	clientID := e4crypto.HashIDAlias("client1")
	clientKey := e4crypto.RandomKey()

	symClient, err := NewClient(&SymIDAndKey{
		ID:  clientID,
		Key: clientKey,
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	return symClient, clientKey
}

func setupForPubClientUnprotectTests(t *testing.T) (Client, []byte, []byte, []byte) {
	clientID := e4crypto.HashIDAlias("client1")
	clientPubKey, clientSKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 keys: %v", err)
	}

	c2PrivKey := e4crypto.RandomKey()
	c2PubKey, err := curve25519.X25519(c2PrivKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to generate curve public key: %v", err)
	}

	sharedKey, err := curve25519.X25519(c2PrivKey, e4crypto.PublicEd25519KeyToCurve25519(clientPubKey))
	if err != nil {
		t.Fatalf("curve25519 X25519 failed: %v", err)
	}
	sharedKey = e4crypto.Sha3Sum256(sharedKey)

	pubClient, err := NewClient(&PubIDAndKey{
		ID:       clientID,
		Key:      clientSKey,
		C2PubKey: c2PubKey,
	}, NewInMemoryStore(nil))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	return pubClient, sharedKey, c2PrivKey, clientPubKey
}

func setTopicKey(t *testing.T, client Client, protectCommandKey []byte, topic string, topicKey []byte) {
	setTopicCmd, err := CmdSetTopicKey(topicKey, topic)
	if err != nil {
		t.Fatalf("CmdSetTopicKey failed: %v", err)
	}

	protectedSetTopicCmd, err := e4crypto.ProtectSymKey(setTopicCmd, protectCommandKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	d, err := client.Unprotect(protectedSetTopicCmd, client.GetReceivingTopic())
	if err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("Expected no returned data, got %v", d)
	}
}

func setPubKey(t *testing.T, client Client, protectCommandKey []byte, pubKeyName string, pubKey []byte) {
	setPubKeyCmd, err := CmdSetPubKey(pubKey, pubKeyName)
	if err != nil {
		t.Fatalf("failed to create SetPubKey command: %v", err)
	}
	protectedSetPubKeyCmd, err := e4crypto.ProtectSymKey(setPubKeyCmd, protectCommandKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	_, err = client.Unprotect(protectedSetPubKeyCmd, client.GetReceivingTopic())
	if err != nil {
		t.Fatalf("Failed to unprotect SetPubKeyCmd: %v", err)
	}

	assertClientPubKey(t, true, client, pubKeyName, pubKey)
}

func testClientSetTopicKey(t *testing.T, client Client, protectCommandKey []byte) {
	topic := "topic1"
	topicKey := e4crypto.RandomKey()

	setTopicKey(t, client, protectCommandKey, topic, topicKey)

	assertClientTopicKey(t, true, client, topic, topicKey)
}

func testClientRemoveTopicKey(t *testing.T, client Client, protectCommandKey []byte) {
	topic1 := "topic1"
	topic1Key1 := e4crypto.RandomKey()
	topic1Key2 := e4crypto.RandomKey()
	topic2 := "topic2"
	topic2Key := e4crypto.RandomKey()

	setTopicKey(t, client, protectCommandKey, topic1, topic1Key1)
	setTopicKey(t, client, protectCommandKey, topic1, topic1Key2) // set topic1Key1 in transitionned state
	setTopicKey(t, client, protectCommandKey, topic2, topic2Key)

	assertClientTopicKey(t, true, client, topic1, topic1Key2)
	assertClientTransitionTopicKey(t, true, client, topic1, topic1Key1)
	assertClientTopicKey(t, true, client, topic2, topic2Key)

	removeTopicCmd, err := CmdRemoveTopic(topic1)
	if err != nil {
		t.Fatalf("failed to create RemoveTopic command: %v", err)
	}
	protectedRemoveTopicCmd, err := e4crypto.ProtectSymKey(removeTopicCmd, protectCommandKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	// Remove the topic key
	d, err := client.Unprotect(protectedRemoveTopicCmd, client.GetReceivingTopic())
	if err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("Invalid unprotect command response, got %v, wanted nil", d)
	}

	assertClientTopicKey(t, false, client, topic1, topic1Key2)
	assertClientTransitionTopicKey(t, false, client, topic1, topic1Key1)
	assertClientTopicKey(t, true, client, topic2, topic2Key)
}

func testClientInvalidSetTopicKey(t *testing.T, client Client, protectCommandKey []byte) {
	topic := "topic1"
	topicKey := e4crypto.RandomKey()
	setTopicCmd, err := CmdSetTopicKey(topicKey, topic)
	if err != nil {
		t.Fatalf("CmdSetTopicKey failed: %v", err)
	}

	badProtectedSetTopicCmd, err := e4crypto.ProtectSymKey(append(setTopicCmd, 0x01), protectCommandKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := client.Unprotect(badProtectedSetTopicCmd, client.GetReceivingTopic()); err == nil {
		t.Fatal("Expected an error with a bad setTopic Command length")
	}

	assertClientTopicKey(t, false, client, topic, topicKey)
}

func testClientInvalidRemoveTopicKey(t *testing.T, client Client, protectCommandKey []byte) {
	// Set a topic key first
	topic := "topic1"
	topicKey := e4crypto.RandomKey()

	setTopicCmd, err := CmdSetTopicKey(topicKey, topic)
	if err != nil {
		t.Fatalf("CmdSetTopicKey failed: %v", err)
	}
	protectedSetTopicCmd, err := e4crypto.ProtectSymKey(setTopicCmd, protectCommandKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := client.Unprotect(protectedSetTopicCmd, client.GetReceivingTopic()); err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}

	assertClientTopicKey(t, true, client, topic, topicKey)

	removeTopicCmd, err := CmdRemoveTopic(topic)
	if err != nil {
		t.Fatalf("failed to create RemoveTopic command: %v", err)
	}
	badProtectedRemoveTopicCmd, err := e4crypto.ProtectSymKey(append(removeTopicCmd, 0x01), protectCommandKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := client.Unprotect(badProtectedRemoveTopicCmd, client.GetReceivingTopic()); err == nil {
		t.Fatal("Expected an error with a bad removeTopic Command length")
	}

	assertClientTopicKey(t, true, client, topic, topicKey)
}

func testClientTopicKeyTransition(t *testing.T, e4client Client, protectCommandKey []byte) {
	topic := "topic1"
	topicKey := e4crypto.RandomKey()

	setTopicKey(t, e4client, protectCommandKey, topic, topicKey)
	assertClientTopicKey(t, true, e4client, topic, topicKey)

	// Add a new topic key for the same topic, old one should still be available
	newTopicKey := e4crypto.RandomKey()
	newSetTopicCmd, err := CmdSetTopicKey(newTopicKey, topic)
	if err != nil {
		t.Fatalf("CmdSetTopicKey failed: %v", err)
	}

	newProtectedSetTopicCmd, err := e4crypto.ProtectSymKey(newSetTopicCmd, protectCommandKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err = e4client.Unprotect(newProtectedSetTopicCmd, e4client.GetReceivingTopic()); err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}

	// Ensure new key is set
	assertClientTopicKey(t, true, e4client, topic, newTopicKey)

	// Ensure old key still present
	assertClientTransitionTopicKey(t, true, e4client, topic, topicKey)
}

func testClientResetTopicKeys(t *testing.T, client Client, protectCommandKey []byte) {
	topic1 := "topic1"
	topic2 := "topic2"
	topic1Key1 := e4crypto.RandomKey()
	topic1Key2 := e4crypto.RandomKey()
	topic2Key := e4crypto.RandomKey()

	setTopicKey(t, client, protectCommandKey, topic1, topic1Key1)
	setTopicKey(t, client, protectCommandKey, topic1, topic1Key2) // set topic1Key1 in transition state
	setTopicKey(t, client, protectCommandKey, topic2, topic2Key)

	resetTopicCmd, err := CmdResetTopics()
	if err != nil {
		t.Fatalf("failed to create ResetTopics command: %v", err)
	}
	protectedResetCmd, err := e4crypto.ProtectSymKey(resetTopicCmd, protectCommandKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	d, err := client.Unprotect(protectedResetCmd, client.GetReceivingTopic())
	if err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("Invalid unprotect command response, got %v, wanted nil", d)
	}

	assertClientTopicKey(t, false, client, topic1, topic1Key1)
	assertClientTransitionTopicKey(t, false, client, topic1, topic1Key2)
	assertClientTopicKey(t, false, client, topic2, topic2Key)
}
func testClientInvalidResetTopicKeys(t *testing.T, client Client, protectCommandKey []byte) {
	topic := "topic1"
	topicKey := e4crypto.RandomKey()

	setTopicKey(t, client, protectCommandKey, topic, topicKey)

	resetTopicCmd, err := CmdResetTopics()
	if err != nil {
		t.Fatalf("failed to create ResetTopics command: %v", err)
	}
	badProtectedResetCmd, err := e4crypto.ProtectSymKey(append(resetTopicCmd, 0x01), protectCommandKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := client.Unprotect(badProtectedResetCmd, client.GetReceivingTopic()); err == nil {
		t.Fatal("Expected an error with a bad reset Command length")
	}

	assertClientTopicKey(t, true, client, topic, topicKey)
}

func testClientInvalidSetPubKey(t *testing.T, client Client, protectCommandKey []byte) {
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate pubkey: %v", err)
	}
	pubKeyName := "anotherClient"
	setPubKeyCmd, err := CmdSetPubKey(pubKey, pubKeyName)
	if err != nil {
		t.Fatalf("failed to create SetPubKey command: %v", err)
	}

	badProtectedSetPubKeyCmd, err := e4crypto.ProtectSymKey(append(setPubKeyCmd, 0x01), protectCommandKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := client.Unprotect(badProtectedSetPubKeyCmd, client.GetReceivingTopic()); err == nil {
		t.Fatal("Expected an error with a bad setPubKey Command length")
	}

	assertClientPubKey(t, false, client, pubKeyName, pubKey)
}

func testClientUnknownCommand(t *testing.T, client Client, protectCommandKey []byte) {
	unknownCmd := []byte{0xFF}
	protectedUnknownCmd, err := e4crypto.ProtectSymKey(unknownCmd, protectCommandKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	_, err = client.Unprotect(protectedUnknownCmd, client.GetReceivingTopic())
	if err != ErrInvalidCommand {
		t.Fatalf("Invalid error when unprotecting command: got %v, wanted %v", err, ErrInvalidCommand)
	}
}

func TestSymClientUnprotect_setTopicKey(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)
	testClientSetTopicKey(t, symClient, clientKey)
}
func TestSymClientUnprotect_invalidSetTopicKey(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)
	testClientInvalidSetTopicKey(t, symClient, clientKey)
}

func TestSymClientUnprotect_removeTopicKey(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)
	testClientRemoveTopicKey(t, symClient, clientKey)
}
func TestSymClientUnprotect_invalidRemoveTopicKey(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)
	testClientInvalidRemoveTopicKey(t, symClient, clientKey)
}

func TestSymClientUnprotect_topicKeyTransition(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)
	testClientTopicKeyTransition(t, symClient, clientKey)
}

func TestSymClientUnprotect_resetTopicKeys(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)
	testClientResetTopicKeys(t, symClient, clientKey)
}
func TestSymClientUnprotect_invalidResetTopicKeys(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)
	testClientInvalidResetTopicKeys(t, symClient, clientKey)
}

func TestSymClientUnprotect_setIDKey(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)

	newClientKey := e4crypto.RandomKey()
	setIDKeyCmd, err := CmdSetIDKey(newClientKey)
	if err != nil {
		t.Fatalf("failed to create SetIDKey command: %v", err)
	}

	protectedSetIDKeyCmd, err := e4crypto.ProtectSymKey(setIDKeyCmd, clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	d, err := symClient.Unprotect(protectedSetIDKeyCmd, symClient.GetReceivingTopic())
	if err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("Expected no returned data, got %v", d)
	}

	// Unprotecting again the same command must fail since the key have changed
	if _, err := symClient.Unprotect(protectedSetIDKeyCmd, symClient.GetReceivingTopic()); err == nil {
		t.Fatal("Expected an error with a command protected with old key")
	}

	// But using the new key must work
	testClientSetTopicKey(t, symClient, newClientKey)
}
func TestSymClientUnprotect_invalidSetIDKey(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)

	newClientKey := e4crypto.RandomKey()
	setIDKeyCmd, err := CmdSetIDKey(newClientKey)
	if err != nil {
		t.Fatalf("failed to create SetIDKey command: %v", err)
	}
	badProtectedSetIDKeyCmd, err := e4crypto.ProtectSymKey(append(setIDKeyCmd, 0x01), clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := symClient.Unprotect(badProtectedSetIDKeyCmd, symClient.GetReceivingTopic()); err == nil {
		t.Fatal("Expected an error with a bad setIDKey Command length")
	}

	// Ensure the original key is still in use
	testClientSetTopicKey(t, symClient, clientKey)
}

func TestSymClientUnprotect_setPubKey(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)

	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate pubkey: %v", err)
	}
	pubKeyName := "anotherClient"

	setPubKeyCmd, err := CmdSetPubKey(pubKey, pubKeyName)
	if err != nil {
		t.Fatalf("failed to create SetPubKey command: %v", err)
	}
	protectedSetPubKeyCmd, err := e4crypto.ProtectSymKey(setPubKeyCmd, clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	_, err = symClient.Unprotect(protectedSetPubKeyCmd, symClient.GetReceivingTopic())
	if err != ErrUnsupportedOperation {
		t.Fatalf("Invalid error when unprotecting command: got %v, wanted %v", err, ErrUnsupportedOperation)
	}
}
func TestSymClientUnprotect_invalidSetPubKey(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)
	testClientInvalidSetPubKey(t, symClient, clientKey)
}

func TestSymClientUnprotect_removePubKey(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)
	pubKeyName := "anotherClient"

	removePubKeyCmd, err := CmdRemovePubKey(pubKeyName)
	if err != nil {
		t.Fatalf("failed to create RemovePubKey command: %v", err)
	}
	protectedRemovePubKeyCmd, err := e4crypto.ProtectSymKey(removePubKeyCmd, clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	_, err = symClient.Unprotect(protectedRemovePubKeyCmd, symClient.GetReceivingTopic())
	if err != ErrUnsupportedOperation {
		t.Fatalf("Invalid error when unprotecting command: got %v, wanted %v", err, ErrUnsupportedOperation)
	}
}
func TestSymClientUnprotect_invalidRemovePubKey(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)
	pubKeyName := "anotherClient"

	removePubKeyCmd, err := CmdRemovePubKey(pubKeyName)
	if err != nil {
		t.Fatalf("failed to create RemovePubKey command: %v", err)
	}
	protectedRemovePubKeyCmd, err := e4crypto.ProtectSymKey(append(removePubKeyCmd, 0x01), clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	_, err = symClient.Unprotect(protectedRemovePubKeyCmd, symClient.GetReceivingTopic())
	if err == nil {
		t.Fatal("Expected an error with a bad RemovePubKey command length")
	}
	if err == ErrUnsupportedOperation {
		t.Fatal("Unexpected ErrUnsupportedOperation' error when  unprotecting command")
	}
}

func TestSymClientUnprotect_resetPubKeys(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)

	resetPubKeysCmd, err := CmdResetPubKeys()
	if err != nil {
		t.Fatalf("failed to create ResetPubKeys command: %v", err)
	}
	protectedResetPubKeysCmd, err := e4crypto.ProtectSymKey(resetPubKeysCmd, clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	_, err = symClient.Unprotect(protectedResetPubKeysCmd, symClient.GetReceivingTopic())
	if err != ErrUnsupportedOperation {
		t.Fatalf("Invalid error when unprotecting command: got %v, wanted %v", err, ErrUnsupportedOperation)
	}
}
func TestSymClientUnprotect_invalidResetPubKeys(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)

	resetPubKeysCmd, err := CmdResetPubKeys()
	if err != nil {
		t.Fatalf("failed to create ResetPubKeys command: %v", err)
	}
	protectedResetPubKeysCmd, err := e4crypto.ProtectSymKey(append(resetPubKeysCmd, 0x01), clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	_, err = symClient.Unprotect(protectedResetPubKeysCmd, symClient.GetReceivingTopic())
	if err == nil {
		t.Fatal("Expected an error with a bad ResetPubKeys command length")
	}
	if err == ErrUnsupportedOperation {
		t.Fatal("Unexpected ErrUnsupportedOperation' error when  unprotecting command")
	}
}
func TestSymClientUnprotect_setC2Key(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)

	newC2PrivKey := e4crypto.RandomKey()
	newC2PubKey, err := curve25519.X25519(newC2PrivKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to generate pubkey: %v", err)
	}

	setC2KeyCmd, err := CmdSetC2Key(newC2PubKey)
	if err != nil {
		t.Fatalf("failed to create SetC2Key command: %v", err)
	}
	protectSetC2KeyCmd, err := e4crypto.ProtectSymKey(setC2KeyCmd, clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	_, err = symClient.Unprotect(protectSetC2KeyCmd, symClient.GetReceivingTopic())
	if err != ErrUnsupportedOperation {
		t.Fatalf("Invalid error when unprotecting command: got %v, wanted %v", err, ErrUnsupportedOperation)
	}
}
func TestSymClientUnprotect_invalidSetC2Key(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)

	newC2PrivKey := e4crypto.RandomKey()
	newC2PubKey, err := curve25519.X25519(newC2PrivKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to generate pubkey: %v", err)
	}

	setC2KeyCmd, err := CmdSetC2Key(newC2PubKey)
	if err != nil {
		t.Fatalf("failed to create SetC2Key command: %v", err)
	}
	protectSetC2KeyCmd, err := e4crypto.ProtectSymKey(setC2KeyCmd, clientKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	_, err = symClient.Unprotect(append(protectSetC2KeyCmd, 0x01), symClient.GetReceivingTopic())
	if err == nil {
		t.Fatal("Expected an error with a bad SetC2Key command length")
	}
	if err == ErrUnsupportedOperation {
		t.Fatal("Unexpected ErrUnsupportedOperation' error when  unprotecting command")
	}
}

func TestSymClientUnprotect_unknownCommand(t *testing.T) {
	symClient, clientKey := setupForSymClientUnprotectTests(t)
	testClientUnknownCommand(t, symClient, clientKey)
}

func TestPubClientUnprotect_setTopicKey(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)
	testClientSetTopicKey(t, pubClient, sharedKey)
}
func TestPubClientUnprotect_invalidSetTopicKey(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)
	testClientInvalidSetTopicKey(t, pubClient, sharedKey)
}

func TestPubClientUnprotect_removeTopicKey(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)
	testClientRemoveTopicKey(t, pubClient, sharedKey)
}
func TestPubClientUnprotect_invalidRemoveTopicKey(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)
	testClientInvalidRemoveTopicKey(t, pubClient, sharedKey)
}

func TestPubClientUnprotect_topicKeyTransition(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)
	testClientTopicKeyTransition(t, pubClient, sharedKey)
}

func TestPubClientUnprotect_resetTopicKeys(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)
	testClientResetTopicKeys(t, pubClient, sharedKey)
}
func TestPubClientUnprotect_invalidResetTopicKeys(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)
	testClientInvalidResetTopicKeys(t, pubClient, sharedKey)
}

func TestPubClientUnprotect_setIDKey(t *testing.T) {
	pubClient, sharedKey, c2PrivKey, _ := setupForPubClientUnprotectTests(t)

	newClientPubKey, newClientKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 keys: %v", err)
	}
	setIDKeyCmd, err := CmdSetIDKey(newClientKey)
	if err != nil {
		t.Fatalf("failed to create SetIDKey command: %v", err)
	}
	protectedSetIDKeyCmd, err := e4crypto.ProtectSymKey(setIDKeyCmd, sharedKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	d, err := pubClient.Unprotect(protectedSetIDKeyCmd, pubClient.GetReceivingTopic())
	if err != nil {
		t.Fatalf("Failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("Expected no returned data, got %v", d)
	}

	// Unprotecting again the same command must fail since the key have changed
	if _, err := pubClient.Unprotect(protectedSetIDKeyCmd, pubClient.GetReceivingTopic()); err == nil {
		t.Fatal("Expected an error with a command protected with old key")
	}

	// But using the new key must work
	newSharedPoint, err := curve25519.X25519(c2PrivKey, e4crypto.PublicEd25519KeyToCurve25519(newClientPubKey))
	if err != nil {
		t.Fatalf("curve25519 X25519 failed: %v", err)
	}
	newSharedKey := e4crypto.Sha3Sum256(newSharedPoint)
	testClientSetTopicKey(t, pubClient, newSharedKey)
}
func TestPubClientUnprotect_invalidSetIDKey(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)

	_, newClientKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 keys: %v", err)
	}
	setIDKeyCmd, err := CmdSetIDKey(newClientKey)
	if err != nil {
		t.Fatalf("failed to create SetIDKey command: %v", err)
	}
	badProtectedSetIDKeyCmd, err := e4crypto.ProtectSymKey(append(setIDKeyCmd, 0x01), sharedKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := pubClient.Unprotect(badProtectedSetIDKeyCmd, pubClient.GetReceivingTopic()); err == nil {
		t.Fatal("Expected an error with a bad setIDKey Command length")
	}

	// Ensure the original key is still in use
	testClientSetTopicKey(t, pubClient, sharedKey)
}

func TestPubClientUnprotect_setPubKey(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)

	pubKeyName := "anotherClient"
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate pubkey: %v", err)
	}

	setPubKey(t, pubClient, sharedKey, pubKeyName, pubKey)
}
func TestPubClientUnprotect_invalidSetPubKey(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)
	testClientInvalidSetPubKey(t, pubClient, sharedKey)
}

func TestPubClientUnprotect_removePubKey(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)

	pubKey1Name := "anotherClient1"
	pubKey1, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate pubkey: %v", err)
	}

	pubKey2Name := "anotherClient2"
	pubKey2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate pubkey: %v", err)
	}

	setPubKey(t, pubClient, sharedKey, pubKey1Name, pubKey1)
	setPubKey(t, pubClient, sharedKey, pubKey2Name, pubKey2)

	assertClientPubKey(t, true, pubClient, pubKey1Name, pubKey1)
	assertClientPubKey(t, true, pubClient, pubKey2Name, pubKey2)

	removePubKeyCmd, err := CmdRemovePubKey(pubKey1Name)
	if err != nil {
		t.Fatalf("Failed to create RemovePubKey command: %v", err)
	}
	protectedRemovePubKeyCmd, err := e4crypto.ProtectSymKey(removePubKeyCmd, sharedKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	_, err = pubClient.Unprotect(protectedRemovePubKeyCmd, pubClient.GetReceivingTopic())
	if err != nil {
		t.Fatalf("Failed to unprotect RemovePubKey command: %v", err)
	}

	assertClientPubKey(t, false, pubClient, pubKey1Name, pubKey1)
	assertClientPubKey(t, true, pubClient, pubKey2Name, pubKey2)
}
func TestPubClientUnprotect_invalidRemovePubKey(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)

	pubKeyName := "anotherClient1"
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate pubkey: %v", err)
	}
	setPubKey(t, pubClient, sharedKey, pubKeyName, pubKey)
	assertClientPubKey(t, true, pubClient, pubKeyName, pubKey)

	removePubKeyCmd, err := CmdRemovePubKey(pubKeyName)
	if err != nil {
		t.Fatalf("Failed to create RemovePubKey command: %v", err)
	}
	badProtectedRemovePubKeyCmd, err := e4crypto.ProtectSymKey(append(removePubKeyCmd, 0x01), sharedKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := pubClient.Unprotect(badProtectedRemovePubKeyCmd, pubClient.GetReceivingTopic()); err == nil {
		t.Fatal("Expected an error with a bad removePubKey Command length")
	}

	assertClientPubKey(t, true, pubClient, pubKeyName, pubKey)
}

func TestPubClientUnprotect_resetPubKeys(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)

	pubKey1Name := "anotherClient1"
	pubKey1, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate pubkey: %v", err)
	}

	pubKey2Name := "anotherClient2"
	pubKey2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate pubkey: %v", err)
	}

	setPubKey(t, pubClient, sharedKey, pubKey1Name, pubKey1)
	setPubKey(t, pubClient, sharedKey, pubKey2Name, pubKey2)

	assertClientPubKey(t, true, pubClient, pubKey1Name, pubKey1)
	assertClientPubKey(t, true, pubClient, pubKey2Name, pubKey2)

	resetPubKeyCmd, err := CmdResetPubKeys()
	if err != nil {
		t.Fatalf("failed to create ResetPubKeys command: %v", err)
	}
	protectedResetPubKeyCmd, err := e4crypto.ProtectSymKey(resetPubKeyCmd, sharedKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	_, err = pubClient.Unprotect(protectedResetPubKeyCmd, pubClient.GetReceivingTopic())
	if err != nil {
		t.Fatalf("Failed to unprotect ResetPubKeys command: %v", err)
	}

	assertClientPubKey(t, false, pubClient, pubKey1Name, pubKey1)
	assertClientPubKey(t, false, pubClient, pubKey2Name, pubKey2)
}
func TestPubClientUnprotect_invalidResetPubKeys(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)

	pubKeyName := "anotherClient1"
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate pubkey: %v", err)
	}
	setPubKey(t, pubClient, sharedKey, pubKeyName, pubKey)
	assertClientPubKey(t, true, pubClient, pubKeyName, pubKey)

	resetPubKeyCmd, err := CmdResetPubKeys()
	if err != nil {
		t.Fatalf("failed to create ResetPubKeys command: %v", err)
	}
	badResetPubKeyCmd, err := e4crypto.ProtectSymKey(append(resetPubKeyCmd, 0x01), sharedKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := pubClient.Unprotect(badResetPubKeyCmd, pubClient.GetReceivingTopic()); err == nil {
		t.Fatal("Expected an error with a bad ResetPubKeys Command length")
	}

	assertClientPubKey(t, true, pubClient, pubKeyName, pubKey)
}

func TestPubClientUnprotect_setC2Key(t *testing.T) {
	pubClient, sharedKey, _, clientPubKey := setupForPubClientUnprotectTests(t)

	newC2PrivKey := e4crypto.RandomKey()
	newC2PubKey, err := curve25519.X25519(newC2PrivKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to generate pubkey: %v", err)
	}
	setC2KeyCmd, err := CmdSetC2Key(newC2PubKey)
	if err != nil {
		t.Fatalf("failed to create SetC2Key command: %v", err)
	}
	protectedSetC2KeyCmd, err := e4crypto.ProtectSymKey(setC2KeyCmd, sharedKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}

	_, err = pubClient.Unprotect(protectedSetC2KeyCmd, pubClient.GetReceivingTopic())
	if err != nil {
		t.Fatalf("Failed to unprotect SetC2Key command: %v", err)
	}

	// Unprotect should now fail since C2 pub key has changed
	_, err = pubClient.Unprotect(protectedSetC2KeyCmd, pubClient.GetReceivingTopic())
	if err == nil {
		t.Fatal("Expected unprotect to fail with a new C2 key")
	}

	newSharedKey, err := curve25519.X25519(newC2PrivKey, e4crypto.PublicEd25519KeyToCurve25519(clientPubKey))
	if err != nil {
		t.Fatalf("curve25519 X25519 failed: %v", err)
	}
	newSharedKey = e4crypto.Sha3Sum256(newSharedKey)

	// Using the new C2 key must work
	testClientSetTopicKey(t, pubClient, newSharedKey)

}
func TestPubClientUnprotect_invalidSetC2Key(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)

	newC2PrivKey := e4crypto.RandomKey()
	newC2PubKey, err := curve25519.X25519(newC2PrivKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to generate pubkey: %v", err)
	}
	setC2KeyCmd, err := CmdSetC2Key(newC2PubKey)
	if err != nil {
		t.Fatalf("failed to create SetC2Key command: %v", err)
	}
	badProtectedSetC2KeyCmd, err := e4crypto.ProtectSymKey(append(setC2KeyCmd, 0x01), sharedKey)
	if err != nil {
		t.Fatalf("Failed to protect command: %v", err)
	}
	if _, err := pubClient.Unprotect(badProtectedSetC2KeyCmd, pubClient.GetReceivingTopic()); err == nil {
		t.Fatal("Expected an error with a bad setC2Key Command length")
	}

	// Using the original C2 key must work
	testClientSetTopicKey(t, pubClient, sharedKey)
}
func TestPubClientUnprotect_unknownCommand(t *testing.T) {
	pubClient, sharedKey, _, _ := setupForPubClientUnprotectTests(t)
	testClientUnknownCommand(t, pubClient, sharedKey)
}

func assertClientTopicKey(t *testing.T, exists bool, e4Client Client, topic string, topicKey []byte) {
	typedClient, ok := e4Client.(*client)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted client", e4Client)
	}

	k, ok := typedClient.TopicKeys[hex.EncodeToString(e4crypto.HashTopic(topic))]
	if exists {
		if !ok {
			t.Fatalf("Expected client to have topic %s key", topic)
		} else if !bytes.Equal(k, topicKey) {
			t.Fatalf("Invalid topic %s key: got %v, wanted %v", topic, k, topicKey)
		}
	} else if ok {
		t.Fatalf("Expected client to not have topic %s key", topic)
	}
}

func assertClientTransitionTopicKey(t *testing.T, exists bool, e4Client Client, topic string, topicKey []byte) {
	typedClient, ok := e4Client.(*client)
	if !ok {
		t.Fatalf("Unexpected type: got %T, wanted client", e4Client)
	}

	hashHash := e4crypto.HashTopic(string(e4crypto.HashTopic(topic)))
	k, ok := typedClient.TopicKeys[hex.EncodeToString(hashHash)]
	if exists {
		if !ok {
			t.Fatalf("Expected client to have topic %s key", topic)
		} else if g, w := len(k), e4crypto.KeyLen+e4crypto.TimestampLen; g != w {
			t.Fatalf("Invalid transition topic key length: got %d, want %d", g, w)
		} else if !bytes.Equal(k[:e4crypto.KeyLen], topicKey) {
			t.Fatalf("Invalid transition topic %s key: got %v, want %v", topic, k, topicKey)
		}
	} else if ok {
		t.Fatalf("Expected client to not have topic %s key", topic)
	}
}

func assertClientPubKey(t *testing.T, exists bool, e4Client Client, keyName string, key []byte) {
	pks, err := e4Client.getPubKeys()
	if err != nil {
		// Make the assert compatible with symClients
		if err != ErrUnsupportedOperation {
			t.Fatalf("Failed to retrieve pubkeys: %v", err)

		}
		pks = make(map[string]ed25519.PublicKey)
	}

	pk, ok := pks[hex.EncodeToString(e4crypto.HashIDAlias(keyName))]
	if exists {
		if !ok {
			t.Fatalf("Expected pubkey for id %s to be set on client", keyName)
		} else if !bytes.Equal(pk, key) {
			t.Fatalf("Invalid pubKey for id %s: got %v, wanted %v", keyName, pk, key)
		}
	} else if ok {
		t.Fatalf("Expected client not having pubkey for id %s", keyName)
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
