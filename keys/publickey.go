package keys

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	e4crypto "gitlab.com/teserakt/e4common/crypto"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

// PubKeyMaterial extends the ClientKey and PubKeyStore interfaces for public key implementations
type PubKeyMaterial interface {
	KeyMaterial
	PubKeyStore
}

// pubKeyMaterial implements PubKeyMaterial to work with public e4 client key
// and PubKeyStore to holds public key needed to verify message signatures
type pubKeyMaterial struct {
	PrivateKey ed25519.PrivateKey `json:"privateKey,omitempty"`
	SignerID   []byte             `json:"signerID,omitempty"`
	C2PubKey   []byte             `json:"c2PubKey,omitempty"`
	PubKeys    map[string][]byte  `json:"pubKeys,omitempty"`

	mutex sync.RWMutex
}

var _ PubKeyMaterial = (*pubKeyMaterial)(nil)

// NewPubKeyMaterial creates a new KeyMaterial to work with public e4 client key
func NewPubKeyMaterial(signerID []byte, privateKey ed25519.PrivateKey, c2PubKey []byte) (PubKeyMaterial, error) {
	if err := e4crypto.ValidateID(signerID); err != nil {
		return nil, fmt.Errorf("invalid signerID: %v", err)
	}

	if err := e4crypto.ValidateEd25519PrivKey(privateKey); err != nil {
		return nil, fmt.Errorf("invalid private key: %v", err)
	}

	if err := e4crypto.ValidateCurve25519PubKey(c2PubKey); err != nil {
		return nil, fmt.Errorf("invalid c2 public key: %v", err)
	}

	e := &pubKeyMaterial{
		C2PubKey: c2PubKey,
		PubKeys:  make(map[string][]byte),
	}

	e.PrivateKey = make([]byte, len(privateKey))
	copy(e.PrivateKey, privateKey)

	e.SignerID = make([]byte, len(signerID))
	copy(e.SignerID, signerID)

	return e, nil
}

// NewPubKeyMaterialFromPassword creates a new PubKeyMaterial e4 client key from given password
func NewPubKeyMaterialFromPassword(signerID []byte, pwd string, c2PubKey []byte) (PubKeyMaterial, error) {
	key, err := e4crypto.Ed25519PrivateKeyFromPassword(pwd)
	if err != nil {
		return nil, err
	}

	return NewPubKeyMaterial(signerID, key, c2PubKey)
}

// NewRandomPubKeyMaterial creates a new PubKeyMaterial key from a random ed25519 key
func NewRandomPubKeyMaterial(signerID []byte, c2PubKey []byte) (PubKeyMaterial, error) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return NewPubKeyMaterial(signerID, privateKey, c2PubKey)
}

// Protect will encrypt and sign the payload with the private key and returns it, or an error if it fail
func (k *pubKeyMaterial) ProtectMessage(payload []byte, topicKey TopicKey) ([]byte, error) {
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

func (k *pubKeyMaterial) UnprotectMessage(protected []byte, topicKey TopicKey) ([]byte, error) {
	if len(protected) <= e4crypto.TimestampLen+ed25519.SignatureSize {
		return nil, e4crypto.ErrInvalidProtectedLen
	}

	// first check timestamp
	timestamp := protected[:e4crypto.TimestampLen]
	if err := e4crypto.ValidateTimestamp(timestamp); err != nil {
		return nil, err
	}

	// then check signature
	signerID := protected[e4crypto.TimestampLen : e4crypto.TimestampLen+e4crypto.IDLen]
	signed := protected[:len(protected)-ed25519.SignatureSize]
	sig := protected[len(protected)-ed25519.SignatureSize:]

	pubkey, err := k.GetPubKey(signerID)
	if err != nil {
		return nil, err
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

func (k *pubKeyMaterial) UnprotectCommand(protected []byte) ([]byte, error) {
	// convert ed key to curve key
	var curvekey [32]byte
	var edkey [64]byte
	copy(edkey[:], k.PrivateKey)
	extra25519.PrivateKeyToCurve25519(&curvekey, &edkey)

	var shared [32]byte
	var c2PubKey [32]byte
	copy(c2PubKey[:], k.C2PubKey[:32])

	curve25519.ScalarMult(&shared, &curvekey, &c2PubKey)

	key := e4crypto.Sha3Sum256(shared[:])[:e4crypto.KeyLen]

	return e4crypto.UnprotectSymKey(protected, key)
}

// AddPubKey store the given id and key in internal storage
// It is safe for concurrent access
func (k *pubKeyMaterial) AddPubKey(id []byte, pubKey []byte) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if err := e4crypto.ValidateEd25519PubKey(pubKey); err != nil {
		return err
	}

	k.PubKeys[hex.EncodeToString(id)] = pubKey

	return nil
}

func (k *pubKeyMaterial) RemovePubKey(id []byte) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	sid := hex.EncodeToString(id)
	_, exists := k.PubKeys[sid]
	if !exists {
		return fmt.Errorf("no public key exists for id: %s", id)
	}

	delete(k.PubKeys, sid)

	return nil
}

func (k *pubKeyMaterial) ResetPubKeys() {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	k.PubKeys = make(map[string][]byte)
}

// GetPubKeys return a map of stored pubKeys, indexed by their hex encoded ids
func (k *pubKeyMaterial) GetPubKeys() map[string][]byte {
	k.mutex.RLock()
	defer k.mutex.RUnlock()

	return k.PubKeys
}

// GetPubKey return a pubKey associated to given ID, or ErrPubKeyNotFound
// when it doesn't exists
func (k *pubKeyMaterial) GetPubKey(id []byte) ([]byte, error) {
	sid := hex.EncodeToString(id)

	key, ok := k.PubKeys[sid]
	if !ok {
		return nil, ErrPubKeyNotFound
	}

	return key, nil
}

// SetKey will validate the given key and copy it into the pubKeyMaterial key when valid
func (k *pubKeyMaterial) SetKey(key []byte) error {
	if err := e4crypto.ValidateEd25519PrivKey(key); err != nil {
		return err
	}

	sk := make([]byte, len(key))
	copy(sk, key)

	k.PrivateKey = sk

	return nil
}

// MarshalJSON  will infer the key type in the marshalled json data
// to be able to know which key to instantiate when unmarshalling back
func (k *pubKeyMaterial) MarshalJSON() ([]byte, error) {
	jsonKey := &jsonKey{
		KeyType: pubKeyMaterialType,
		KeyData: struct {
			PrivateKey ed25519.PrivateKey
			SignerID   []byte
			C2PubKey   []byte
			PubKeys    map[string][]byte
		}{
			PrivateKey: k.PrivateKey,
			SignerID:   k.SignerID,
			C2PubKey:   k.C2PubKey,
			PubKeys:    k.PubKeys,
		},
	}

	return json.Marshal(jsonKey)
}
