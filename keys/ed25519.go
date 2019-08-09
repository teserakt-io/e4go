package keys

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	e4crypto "gitlab.com/teserakt/e4common/crypto"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

// Ed25519Key extends the ClientKey and PubKeyStore interfaces for Ed25519 key implementations
type Ed25519Key interface {
	ClientKey
	PubKeyStore
}

// Ed25519Key implements ClientKey for a Ed25519 private key
// and PubKeyStore to holds public key needed to verify message signatures
type ed25519Key struct {
	PrivateKey  ed25519.PrivateKey
	SignerID    []byte
	C2PublicKey [32]byte
	PubKeys     map[string][]byte

	mutex sync.RWMutex
}

var _ Ed25519Key = (*ed25519Key)(nil)

// NewEd25519Key creates a new Ed25519 e4 client key
func NewEd25519Key(signerID []byte, privateKey ed25519.PrivateKey, c2PublicKey [32]byte) (Ed25519Key, error) {
	if len(signerID) != e4crypto.IDLen {
		return nil, fmt.Errorf("invalid signerID len, expected %d, got %d", e4crypto.IDLen, len(signerID))
	}

	if err := e4crypto.ValidEd25519PrivKey(privateKey); err != nil {
		return nil, err
	}

	e := &ed25519Key{
		C2PublicKey: c2PublicKey,
		PubKeys:     make(map[string][]byte),
	}

	e.PrivateKey = make([]byte, len(privateKey))
	copy(e.PrivateKey, privateKey)

	e.SignerID = make([]byte, len(signerID))
	copy(e.SignerID, signerID)

	return e, nil
}

// NewEd25519KeyFromPassword creates a new ed25519 e4 client key from given password
func NewEd25519KeyFromPassword(signerID []byte, pwd string, c2Key [32]byte) (Ed25519Key, error) {
	return NewEd25519Key(signerID, e4crypto.Ed25519PrivateKeyFromPassword(pwd), c2Key)
}

// NewRandomEd25519Key creates a new Ed25519 key from a random value
func NewRandomEd25519Key(signerID []byte, c2Key [32]byte) (Ed25519Key, error) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return NewEd25519Key(signerID, privateKey, c2Key)
}

// Protect will encrypt and sign the payload with the private key and returns it, or an error if it fail.
func (k *ed25519Key) ProtectMessage(payload []byte, topicKey TopicKey) ([]byte, error) {
	timestamp := make([]byte, e4crypto.TimestampLen)
	binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().Unix()))

	ct, err := e4crypto.Encrypt(topicKey, timestamp, payload)
	if err != nil {
		return nil, err
	}

	protected := append(timestamp, k.SignerID...)
	protected = append(protected, ct...)

	// sig should always be ed25519.SignatureSize=64 bytes
	sig := ed25519.Sign(k.PrivateKey, protected)
	if len(sig) != ed25519.SignatureSize {
		return nil, ErrInvalidSignature
	}

	protected = append(protected, sig...)
	protectedLen := e4crypto.TimestampLen + e4crypto.IDLen + len(payload) + e4crypto.TagLen + ed25519.SignatureSize
	if protectedLen != len(protected) {
		return nil, e4crypto.ErrInvalidProtectedLen
	}

	return protected, nil
}

func (k *ed25519Key) UnprotectMessage(protected []byte, topicKey TopicKey) ([]byte, error) {
	if len(protected) <= e4crypto.TimestampLen+ed25519.SignatureSize {
		return nil, e4crypto.ErrInvalidProtectedLen
	}

	// first check timestamp
	timestamp := protected[:e4crypto.TimestampLen]
	if err := e4crypto.ValidateTimestamp(timestamp); err != nil {
		return nil, err
	}

	// then check signature
	signerID := string(protected[e4crypto.TimestampLen : e4crypto.TimestampLen+e4crypto.IDLen])
	signed := protected[:len(protected)-ed25519.SignatureSize]
	sig := protected[len(protected)-ed25519.SignatureSize:]

	pubkey, ok := k.PubKeys[signerID]
	if !ok {
		return nil, ErrPubKeyNotFound
	}

	if !ed25519.Verify(ed25519.PublicKey(pubkey), signed, sig) {
		return nil, ErrInvalidSignature
	}

	ct := protected[e4crypto.TimestampLen+e4crypto.IDLen : len(protected)-ed25519.SignatureSize]

	// finally decrypt
	pt, err := e4crypto.Decrypt(topicKey, timestamp, ct)
	if err != nil {
		return nil, err
	}

	return pt, nil
}

func (k *ed25519Key) UnprotectCommand(protected []byte) ([]byte, error) {
	// convert ed key to curve key
	var curvekey [32]byte
	var edkey [64]byte
	copy(edkey[:], k.PrivateKey)
	extra25519.PrivateKeyToCurve25519(&curvekey, &edkey)

	var shared [32]byte
	curve25519.ScalarMult(&shared, &curvekey, &k.C2PublicKey)

	key := e4crypto.Sha3Sum256(shared[:])[:e4crypto.KeyLen]

	return e4crypto.UnprotectSymKey(protected, key)
}

// AddPubKey store the given id and key in internal storage.
// It is safe for concurrent access.
func (k *ed25519Key) AddPubKey(id string, pubKey []byte) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	// TODO: validate this check
	if err := e4crypto.ValidateEd25519PubKey(pubKey); err != nil {
		return err
	}

	k.PubKeys[id] = pubKey

	return nil
}

func (k *ed25519Key) RemovePubKey(id string) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	_, exists := k.PubKeys[id]
	if !exists {
		return fmt.Errorf("no public key exists for id: %s", id)
	}

	delete(k.PubKeys, id)

	return nil
}

func (k *ed25519Key) ResetPubKeys() {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	k.PubKeys = make(map[string][]byte)
}

// SetKey will validate the given key and copy it into the ed25519Key key when valid
func (k *ed25519Key) SetKey(key []byte) error {
	if err := e4crypto.ValidEd25519PrivKey(key); err != nil {
		return err
	}

	sk := make([]byte, len(key))
	copy(sk, key)

	k.PrivateKey = sk

	return nil
}

// MarshalJSON  will infer the key type in the marshalled json data
// to be able to know which key to instanciate when unmarshalling back.
func (k *ed25519Key) MarshalJSON() ([]byte, error) {
	jsonKey := &jsonKey{
		KeyType: ed25519KeyType,
		KeyData: struct {
			PrivateKey  ed25519.PrivateKey
			SignerID    []byte
			C2PublicKey [32]byte
			PubKeys     map[string][]byte
		}{
			PrivateKey:  k.PrivateKey,
			SignerID:    k.SignerID,
			C2PublicKey: k.C2PublicKey,
			PubKeys:     k.PubKeys,
		},
	}

	return json.Marshal(jsonKey)
}
