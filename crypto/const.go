// Copyright 2018-2019-2020 Teserakt AG
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

import "time"

// List of global e4 constants
const (
	// IDLen is the length of an E4 ID
	IDLen = 16
	// KeyLen is the length of a symmetric key
	KeyLen = 32
	// TagLen is the length of the authentication tag appended to the cipher
	TagLen = 16
	// HashLen is the length of a hashed topic
	HashLen = 16
	// TimestampLen is the length of the timestamp
	TimestampLen = 8
	// MaxTopicLen is the maximum length of a topic
	MaxTopicLen = 512
	// MaxDelayDuration is the validity time of a protected message
	MaxDelayDuration = 10 * time.Minute
	// MaxDelayKeyTransition is the validity time of an old topic key once updated
	MaxDelayKeyTransition = 60 * time.Minute
	// IDLenHex is the length of a hexadecimal encoded ID
	IDLenHex = IDLen * 2
	// KeyLenHex is the length of a hexadecimal encoded key
	KeyLenHex = KeyLen * 2

	// Curve25519PubKeyLen is the length of a curve25519 public key
	Curve25519PubKeyLen = 32
	// Curve25519PrivKeyLen is the length of a curve25519 private key
	Curve25519PrivKeyLen = 32
)
