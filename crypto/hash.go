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

package crypto

import "golang.org/x/crypto/sha3"

// Sha3Sum256 returns the sha3 sum of given data
func Sha3Sum256(data []byte) []byte {
	h := sha3.Sum256(data)
	return h[:]
}

// HashTopic creates a topic hash from a topic string
func HashTopic(topic string) []byte {
	return Sha3Sum256([]byte(topic))[:HashLen]
}

// HashIDAlias creates an ID from an ID alias string
func HashIDAlias(idalias string) []byte {
	return Sha3Sum256([]byte(idalias))[:IDLen]
}
