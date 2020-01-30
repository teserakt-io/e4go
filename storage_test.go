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
	"io"
	"testing"
)

func TestMemoryStore(t *testing.T) {
	store := NewMemoryStore(nil)

	expected := []byte("abcde")

	n, err := store.Write(expected)
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(expected) {
		t.Fatalf("expected n to be %d, got %d", len(expected), n)
	}

	readBuf := make([]byte, len(expected))
	_, err = store.Read(readBuf)
	if err != io.EOF {
		t.Fatalf("expected read EOF, got %v", err)
	}

	idx, err := store.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("unexpected seek error: %v", err)
	}
	if idx != 0 {
		t.Fatalf("unexpected idx, want %d, got %d", 0, idx)
	}

	n, err = store.Read(readBuf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if n != len(expected) {
		t.Fatalf("expected n to be %d, got %d", len(expected), n)
	}
	if !bytes.Equal(readBuf, expected) {
		t.Fatalf("expected readBuf to be %v, got %v", expected, readBuf)
	}

	idx, err = store.Seek(-2, io.SeekEnd)
	if err != nil {
		t.Fatalf("unexpected seek error: %v", err)
	}
	if idx != int64(len(expected)-2) {
		t.Fatalf("unexpected idx, want %d, got %d", len(expected)-2, idx)
	}

	readBuf = make([]byte, len(expected)-3)
	n, err = store.Read(readBuf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if n != len(expected)-3 {
		t.Fatalf("expected n to be %d, got %d", len(expected)-3, n)
	}
	if !bytes.Equal(readBuf, expected[3:]) {
		t.Fatalf("expected readBuf to be %v, got %v", expected[3:], readBuf)
	}

	idx, err = store.Seek(-1, io.SeekCurrent)
	if err != nil {
		t.Fatalf("unexpected seek error: %v", err)
	}
	if idx != int64(len(expected)-1) {
		t.Fatalf("unexpected idx, want %d, got %d", len(expected)-1, idx)
	}

	readBuf = make([]byte, 1)
	n, err = store.Read(readBuf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected n to be %d, got %d", 1, n)
	}
	if !bytes.Equal(readBuf, expected[len(expected)-1:]) {
		t.Fatalf("expected readBuf to be %v, got %v", expected[len(expected)-1:], readBuf)
	}
}
