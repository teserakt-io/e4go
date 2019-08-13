package e4common

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

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

	if _, ok := c1.Key.(keys.SymKeyMaterial); !ok {
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

	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	client, err := NewPubKeyClient(clientID, privateKey, "./test/data/clienttestprotectPubKey", generateCurve25519PubKey(t))
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

		// happy case
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
		ts := time.Unix(int64(binary.LittleEndian.Uint64(timestamporig)), 0)
		tsf := ts.Add(1000000 * time.Second)
		tsp := ts.Add(-(e4crypto.MaxSecondsDelay + 1))
		tsfuture := make([]byte, 8)
		tspast := make([]byte, 8)
		binary.LittleEndian.PutUint64(tsfuture, uint64(tsf.Unix()))
		binary.LittleEndian.PutUint64(tspast, uint64(tsp.Unix()))

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

	if _, err := c.ProtectMessage([]byte("payload"), "topic-not-existing"); err != ErrTopicKeyNotFound {
		t.Fatalf("expected ProtectMessage for an unknow topic to return error %v, got %v", ErrTopicKeyNotFound, err)
	}

	if _, err := c.Unprotect([]byte("protected"), "topic-not-existing"); err != ErrTopicKeyNotFound {
		t.Fatalf("expected Unprotect for an unknow topic to return error %v, got %v", ErrTopicKeyNotFound, err)
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
	gc, err := NewPubKeyClient(clientID, clientEdSk, "./test/data/clienttestcommand", c2pk[:])
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

func TestClientPubKeys(t *testing.T) {
	t.Run("pubKey client properly add / remove / reset pubKeys", func(t *testing.T) {
		clientFilePath := "./test/data/pubclienttestpubkeys"

		c, err := NewPubKeyClientPretty("testClient", "passwordTestRandom", clientFilePath, generateCurve25519PubKey(t))
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		pks, err := c.GetPubKeys()
		if err != nil {
			t.Fatalf("failed to retrieve pubkeys: %v", err)
		}

		if len(pks) != 0 {
			t.Fatalf("expected no pubkeys, got %#v", pks)
		}

		id1 := e4crypto.RandomID()
		pubKey1, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("failed to generate pubKey: %v", err)
		}

		if err := c.SetPubKey(pubKey1, id1); err != nil {
			t.Fatalf("failed to set pubkey: %v", err)
		}

		assertContainsPubKey(t, c, id1, pubKey1)
		assertSavedClientPubKeysEquals(t, clientFilePath, c)

		id2 := e4crypto.RandomID()
		pubKey2, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("failed to generate pubKey: %v", err)
		}

		if err := c.SetPubKey(pubKey2, id2); err != nil {
			t.Fatalf("failed to set pubkey: %v", err)
		}

		assertContainsPubKey(t, c, id1, pubKey1)
		assertContainsPubKey(t, c, id2, pubKey2)
		assertSavedClientPubKeysEquals(t, clientFilePath, c)

		id3 := e4crypto.RandomID()
		if err := c.RemovePubKey(id3); err == nil {
			t.Fatal("expected removal of pubKey with unknow ID to produce an error")
		}

		if err := c.RemovePubKey(id1); err != nil {
			t.Fatalf("failed to remove a known pubKey: %v", err)
		}

		assertContainsPubKey(t, c, id2, pubKey2)
		assertSavedClientPubKeysEquals(t, clientFilePath, c)

		pks, err = c.GetPubKeys()
		if err != nil {
			t.Fatalf("failed to retrieve pubkeys: %v", err)
		}

		if _, ok := pks[string(id1)]; ok {
			t.Fatal("expected pubKey to have been removed")
		}

		if err := c.ResetPubKeys(); err != nil {
			t.Fatalf("failed to reset pubKeys: %v", err)
		}

		pks, err = c.GetPubKeys()
		if err != nil {
			t.Fatalf("failed to retrieve pubkeys: %v", err)
		}

		if len(pks) != 0 {
			t.Fatalf("expected empty public keys map, got %#v", pks)
		}

		assertSavedClientPubKeysEquals(t, clientFilePath, c)
	})

	t.Run("pubKey client return errors on pubKey operations with invalid ids", func(t *testing.T) {
		clientFilePath := "./test/data/pubclienttestpubkeys"

		c, err := NewPubKeyClientPretty("testClient", "passwordTestRandom", clientFilePath, generateCurve25519PubKey(t))
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		pk, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("failed to generate publicKey: %v", err)
		}

		if err := c.SetPubKey(pk, []byte("bad id")); err == nil {
			t.Fatal("expected an error when setting a pubkey with an invalid id")
		}

		if err := c.RemovePubKey([]byte("bad id")); err == nil {
			t.Fatal("expected an error when setting a pubkey with an invalid id")
		}
	})

	t.Run("symClient must return unsupported operations on pubKey methods", func(t *testing.T) {
		symClient, err := NewSymKeyClientPretty("testClient", "passwordTestRandom", "./symclienttestpubkeys")
		if err != nil {
			t.Fatalf("failed to create symClient: %v", err)
		}

		if _, err := symClient.GetPubKeys(); err != ErrUnsupportedOperation {
			t.Fatalf("expected err to be %v, got %v", ErrUnsupportedOperation, err)
		}

		if err := symClient.SetPubKey([]byte{}, []byte{}); err != ErrUnsupportedOperation {
			t.Fatalf("expected err to be %v, got %v", ErrUnsupportedOperation, err)
		}

		if err := symClient.RemovePubKey([]byte{}); err != ErrUnsupportedOperation {
			t.Fatalf("expected err to be %v, got %v", ErrUnsupportedOperation, err)
		}

		if err := symClient.ResetPubKeys(); err != ErrUnsupportedOperation {
			t.Fatalf("expected err to be %v, got %v", ErrUnsupportedOperation, err)
		}
	})
}

func TestClientTopics(t *testing.T) {
	t.Run("topic key operations properly update client state", func(t *testing.T) {
		symClient, err := NewSymKeyClientPretty("clientID", "passwordTestRandom", "./test/data/testclienttopics")
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		tSymClient, ok := symClient.(*client)
		if !ok {
			t.Fatal("failed to cast client")
		}

		if c := len(tSymClient.TopicKeys); c != 0 {
			t.Fatalf("expected client to be initialized with no topic keys, got %d", c)
		}

		topicKey1 := e4crypto.RandomKey()
		topicHash1 := e4crypto.HashTopic("topic1")

		if err := tSymClient.SetTopicKey(topicKey1, topicHash1); err != nil {
			t.Fatalf("failed to set topic key: %v", err)
		}
		assertClientTopicKey(t, true, tSymClient, topicHash1, topicKey1)

		topicKey2 := e4crypto.RandomKey()
		topicHash2 := e4crypto.HashTopic("topic2")

		if err := tSymClient.SetTopicKey(topicKey2, topicHash2); err != nil {
			t.Fatalf("failed to set topic key: %v", err)
		}

		assertClientTopicKey(t, true, tSymClient, topicHash1, topicKey1)
		assertClientTopicKey(t, true, tSymClient, topicHash2, topicKey2)

		if err := tSymClient.RemoveTopic(topicHash1); err != nil {
			t.Fatalf("failed to remove topic key: %v", err)
		}

		if c := len(tSymClient.TopicKeys); c != 1 {
			t.Fatalf("expected 1 topic key, got %d", c)
		}

		assertClientTopicKey(t, false, tSymClient, topicHash1, nil)
		assertClientTopicKey(t, true, tSymClient, topicHash2, topicKey2)

		if err := tSymClient.ResetTopics(); err != nil {
			t.Fatalf("failed to reset topics: %v", err)
		}
		if c := len(tSymClient.TopicKeys); c != 0 {
			t.Fatalf("expected no topic key, got %d", c)
		}
	})

	t.Run("topic key operations returns errors when invoked with bad topic hashes", func(t *testing.T) {
		symClient, err := NewSymKeyClientPretty("clientID", "passwordTestRandom", "./test/data/testclienttopics")
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		topicKey := e4crypto.RandomKey()

		if err := symClient.SetTopicKey(topicKey, []byte("bad hash")); err == nil {
			t.Fatal("expected setTopicKey to fail with a bad topic hash")
		}

		if err := symClient.RemoveTopic([]byte("bad hash")); err == nil {
			t.Fatal("expected RemoveTopic to fail with a bad topic hash")
		}
	})
}

func TestCommandsSymClient(t *testing.T) {
	clientID := e4crypto.HashIDAlias("client1")
	clientKey := e4crypto.RandomKey()

	c, err := NewSymKeyClient(clientID, clientKey, "./test/data/testcommandsclient")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	receivingTopic := topicForID(clientID)

	setTopicCmd := []byte{SetTopicKey.ToByte()}
	topicKey := e4crypto.RandomKey()
	setTopicCmd = append(setTopicCmd, topicKey...)
	topicHash := e4crypto.HashTopic("topic1")
	setTopicCmd = append(setTopicCmd, topicHash...)

	protectedSetTopicCmd, err := e4crypto.ProtectSymKey(setTopicCmd, clientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}

	badProtectedSetTopicCmd, err := e4crypto.ProtectSymKey(append(setTopicCmd, 0x01), clientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedSetTopicCmd, receivingTopic); err == nil {
		t.Fatal("expected an error with a bad setTopic Command length")
	}

	// Add the topic key
	d, err := c.Unprotect(protectedSetTopicCmd, receivingTopic)
	if err != nil {
		t.Fatalf("failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("expected no returned data, got %v", d)
	}

	assertClientTopicKey(t, true, c, topicHash, topicKey)

	removeTopicCmd := []byte{RemoveTopic.ToByte()}
	removeTopicCmd = append(removeTopicCmd, topicHash...)

	protectedRemoveTopicCmd, err := e4crypto.ProtectSymKey(removeTopicCmd, clientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}

	badProtectedRemoveTopicCmd, err := e4crypto.ProtectSymKey(append(removeTopicCmd, 0x01), clientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedRemoveTopicCmd, receivingTopic); err == nil {
		t.Fatal("expected an error with a bad removeTopic Command length")
	}

	// Remove the topic key
	d, err = c.Unprotect(protectedRemoveTopicCmd, receivingTopic)
	if err != nil {
		t.Fatalf("failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("expected no returned data, got %v", d)
	}

	assertClientTopicKey(t, false, c, topicHash, nil)

	// Add back the topic key
	d, err = c.Unprotect(protectedSetTopicCmd, receivingTopic)
	if err != nil {
		t.Fatalf("failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("expected no returned data, got %v", d)
	}

	assertClientTopicKey(t, true, c, topicHash, topicKey)

	// Reset topics
	resetTopicCmd := []byte{ResetTopics.ToByte()}
	protectedResetCmd, err := e4crypto.ProtectSymKey(resetTopicCmd, clientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}

	badProtectedResetCmd, err := e4crypto.ProtectSymKey(append(resetTopicCmd, 0x01), clientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedResetCmd, receivingTopic); err == nil {
		t.Fatal("expected an error with a bad reset Command length")
	}

	d, err = c.Unprotect(protectedResetCmd, receivingTopic)
	if err != nil {
		t.Fatalf("failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("expected no returned data, got %v", d)
	}

	assertClientTopicKey(t, false, c, topicHash, topicKey)

	// SetIDKey
	setIDKeyCmd := []byte{SetIDKey.ToByte()}

	newClientKey := e4crypto.RandomKey()
	setIDKeyCmd = append(setIDKeyCmd, newClientKey...)

	protectedSetIDKeyCmd, err := e4crypto.ProtectSymKey(setIDKeyCmd, clientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}

	badProtectedSetIDKeyCmd, err := e4crypto.ProtectSymKey(append(setIDKeyCmd, 0x01), clientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedSetIDKeyCmd, receivingTopic); err == nil {
		t.Fatal("expected an error with a bad setIDKey Command length")
	}

	d, err = c.Unprotect(protectedSetIDKeyCmd, receivingTopic)
	if err != nil {
		t.Fatalf("failed to unprotect command: %v", err)
	}
	if d != nil {
		t.Fatalf("expected no returned data, got %v", d)
	}

	// Unprotecting again the same command must fail since the key have changed
	if _, err := c.Unprotect(protectedSetIDKeyCmd, receivingTopic); err == nil {
		t.Fatal("expected an error with a command protected with old key")
	}

	setPubKeyCmd := []byte{SetPubKey.ToByte()}
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate pubkey: %v", err)
	}
	setPubKeyCmd = append(setPubKeyCmd, pubKey...)

	pubKeyID := e4crypto.RandomID()
	setPubKeyCmd = append(setPubKeyCmd, pubKeyID...)
	protectedSetPubKeyCmd, err := e4crypto.ProtectSymKey(setPubKeyCmd, newClientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}

	badProtectedSetPubKeyCmd, err := e4crypto.ProtectSymKey(append(setPubKeyCmd, 0x01), newClientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedSetPubKeyCmd, receivingTopic); err == nil {
		t.Fatal("expected an error with a bad setIDKey Command length")
	}

	_, err = c.Unprotect(protectedSetPubKeyCmd, receivingTopic)
	if err != ErrUnsupportedOperation {
		t.Fatalf("expected symClient to return %v, got %v", ErrUnsupportedOperation, err)
	}

	// RemovePubKey
	removePubKeyCmd := []byte{RemovePubKey.ToByte()}
	removePubKeyCmd = append(removePubKeyCmd, pubKeyID...)

	protectedRemovePubKeyCmd, err := e4crypto.ProtectSymKey(removePubKeyCmd, newClientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}

	badProtectedRemovePubKeyCmd, err := e4crypto.ProtectSymKey(append(removePubKeyCmd, 0x01), newClientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedRemovePubKeyCmd, receivingTopic); err == nil {
		t.Fatal("expected an error with a bad setIDKey Command length")
	}

	_, err = c.Unprotect(protectedRemovePubKeyCmd, receivingTopic)
	if err != ErrUnsupportedOperation {
		t.Fatalf("expected symClient to return %v, got %v", ErrUnsupportedOperation, err)
	}

	// ResetPubKeys
	resetPubKeyCmd := []byte{ResetPubKeys.ToByte()}

	protectedResetPubKeyCmd, err := e4crypto.ProtectSymKey(resetPubKeyCmd, newClientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}

	badProtectedResetPubKeyCmd, err := e4crypto.ProtectSymKey(append(resetPubKeyCmd, 0x01), newClientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}
	if _, err := c.Unprotect(badProtectedResetPubKeyCmd, receivingTopic); err == nil {
		t.Fatal("expected an error with a bad setIDKey Command length")
	}

	_, err = c.Unprotect(protectedResetPubKeyCmd, receivingTopic)
	if err != ErrUnsupportedOperation {
		t.Fatalf("expected symClient to return %v, got %v", ErrUnsupportedOperation, err)
	}

	// Unknow command
	unknowCmd := []byte{0xFF}
	protectedUnknowCmd, err := e4crypto.ProtectSymKey(unknowCmd, newClientKey)
	if err != nil {
		t.Fatalf("failed to protect command: %v", err)
	}

	_, err = c.Unprotect(protectedUnknowCmd, receivingTopic)
	if err != ErrInvalidCommand {
		t.Fatalf("expected symClient to return %v, got %v", ErrInvalidCommand, err)
	}
}

func assertClientTopicKey(t *testing.T, exists bool, c Client, topicHash []byte, topicKey []byte) {
	tc, ok := c.(*client)
	if !ok {
		t.Fatal("failed to cast client")
	}

	k, ok := tc.TopicKeys[hex.EncodeToString(topicHash)]
	if exists && !ok {
		t.Fatalf("expected client to have topic %s key", hex.EncodeToString(topicHash))
	} else if !exists && ok {
		t.Fatalf("expected client to not have topic %s key", hex.EncodeToString(topicHash))
	}

	if exists {
		if bytes.Equal(k, topicKey) == false {
			t.Fatalf("expected topic key to be %v, got %v", topicKey, k)
		}
	}
}

func assertContainsPubKey(t *testing.T, c Client, id []byte, key []byte) {
	pks, err := c.GetPubKeys()
	if err != nil {
		t.Fatalf("failed to retrieve pubkeys: %v", err)
	}

	pk, ok := pks[hex.EncodeToString(id)]
	if !ok {
		t.Fatal("expected pubkey to be set on client")
	}
	if bytes.Equal(pk, key) == false {
		t.Fatalf("expected pubKey to be %v, got %v", key, pk)
	}
}

func assertSavedClientPubKeysEquals(t *testing.T, filepath string, c Client) {
	savedClient, err := LoadClient(filepath)
	if err != nil {
		t.Fatalf("failed to load client: %v", err)
	}

	savedPk, err := savedClient.GetPubKeys()
	if err != nil {
		t.Fatalf("failed to get savedClient pubKeys: %v", err)
	}
	cPk, err := c.GetPubKeys()
	if err != nil {
		t.Fatalf("failed to get client pubKeys: %v", err)
	}
	if reflect.DeepEqual(savedPk, cPk) == false {
		t.Fatalf("expected savedClient pubKeys to be %#v, got %#v", cPk, savedPk)
	}
}

func generateCurve25519PubKey(t *testing.T) []byte {
	var c2PubKey [32]byte

	c2EdPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate c2 public key: %v", err)
	}

	var c2EdPk [32]byte
	copy(c2EdPk[:], c2EdPubKey)

	extra25519.PublicKeyToCurve25519(&c2PubKey, &c2EdPk)

	return c2PubKey[:]
}
