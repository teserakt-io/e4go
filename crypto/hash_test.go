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

import (
	"encoding/hex"
	"testing"
)

/* TestHash tests KATs for both the hash function of choice and
 * the password hashing function / KDF of choice */
func TestHash(t *testing.T) {
	h := hex.EncodeToString(HashIDAlias("abc"))
	expected := "3a985da74fe225b2045c172d6bd390bd"
	if h != expected {
		t.Fatalf("Hash of ID alias incorrect, got: %s, wanted: %s", h, expected)
	}

	k, err := DeriveSymKey("testRandomPassword")
	if err != nil {
		t.Fatalf("Failed to derive symkey: %v", err)
	}

	h = hex.EncodeToString(k)
	expected = "ae153aa9dad7a10b0aed6d5bcfb407c77066acfbb2eaa702a6a88b6cf1b88c33"
	if h != expected {
		t.Fatalf("Hash of password incorrect, got: %s, wanted: %s", h, expected)
	}

	h = hex.EncodeToString(HashTopic("abc"))
	expected = "3a985da74fe225b2045c172d6bd390bd"
	if h != expected {
		t.Fatalf("Hash of Topic incorrect, got: %s, wanted: %s", h, expected)
	}
}
