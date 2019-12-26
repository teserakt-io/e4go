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

package keys

import (
	"encoding/json"
	"fmt"
)

type keyType int

// List of keyType for each KeyMaterial
const (
	// symKeyMaterialType defines a keyType for the SymKeyMaterial implementation
	symKeyMaterialType keyType = iota
	// pubKeyMaterialType defines a keyType for the PubKeyMaterial implementation
	pubKeyMaterialType
)

// jsonKey defines a wrapper type to json encode a KeyMaterial.
// It's needed to store the actual key type in the marshalled json
// thus allowing to decode the key later to the proper type.
type jsonKey struct {
	KeyType keyType     `json:"keyType"`
	KeyData interface{} `json:"keyData"`
}

// FromRawJSON allows to unmarshal a json encoded jsonKey from a json RawMessage
// It returns a ready to use KeyMaterial, or an error if it cannot decode it.
func FromRawJSON(raw json.RawMessage) (KeyMaterial, error) {
	m := make(map[string]json.RawMessage)
	err := json.Unmarshal(raw, &m)
	if err != nil {
		return nil, err
	}

	if _, ok := m["keyType"]; !ok {
		return nil, fmt.Errorf("invalid json raw message, expected \"keyType\"")
	}
	if _, ok := m["keyData"]; !ok {
		return nil, fmt.Errorf("invalid json raw message, expected \"keyData\"")
	}

	var t keyType
	if err := json.Unmarshal(m["keyType"], &t); err != nil {
		return nil, err
	}

	var clientKey KeyMaterial
	switch t {
	case symKeyMaterialType:
		clientKey = &symKeyMaterial{}
	case pubKeyMaterialType:
		clientKey = &pubKeyMaterial{}
	default:
		return nil, fmt.Errorf("unsupported json key type: %v", t)
	}

	if err := json.Unmarshal(m["keyData"], clientKey); err != nil {
		return nil, err
	}

	return clientKey, nil
}
