// Copyright 2020 Teserakt AG
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
	"errors"
	"io"
)

// ReadWriteSeeker is a redefinition of io.ReadWriteSeeker
// to ensure that gomobile bindings still get generated without
// incompatible type removals
type ReadWriteSeeker interface {
	io.ReadWriteSeeker
}

type inMemoryStore struct {
	buf   *bytes.Buffer
	index int64
}

var _ ReadWriteSeeker = (*inMemoryStore)(nil)

// NewInMemoryStore creates a new ReadWriteSeeker in memory
func NewInMemoryStore(buf []byte) ReadWriteSeeker {
	return &inMemoryStore{
		buf: bytes.NewBuffer(buf),
	}
}

func (s *inMemoryStore) Write(p []byte) (n int, err error) {
	if s.index < 0 {
		return 0, io.EOF
	}

	idx := int(s.index)
	bufLen := s.buf.Len()
	if idx != bufLen && idx <= bufLen {
		bufSlice := s.buf.Bytes()[:s.index]
		s.buf = bytes.NewBuffer(bufSlice)
	}

	n, err = s.buf.Write(p)
	s.index += int64(n)

	return n, err
}

func (s *inMemoryStore) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	if s.index >= int64(s.buf.Len()) {
		return 0, io.EOF
	}

	bufSlice := s.buf.Bytes()[s.index:]
	n, err = bytes.NewBuffer(bufSlice).Read(b)
	s.index += int64(n)

	return n, err
}

func (s *inMemoryStore) Seek(offset int64, whence int) (idx int64, err error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = int64(s.index) + offset
	case io.SeekEnd:
		abs = int64(s.buf.Len()) + offset
	default:
		return 0, errors.New("invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("negative position")
	}

	s.index = abs
	return abs, nil
}
