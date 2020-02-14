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
	"errors"
	"fmt"
	"io"
)

// ReadWriteSeeker is a redefinition of io.ReadWriteSeeker
// to ensure that gomobile bindings still get generated without
// incompatible type removals
type ReadWriteSeeker interface {
	io.ReadWriteSeeker
}

type inMemoryStore struct {
	buf   []byte
	index int
}

var _ ReadWriteSeeker = (*inMemoryStore)(nil)

// maxInt holds the maximum int value for the current architecture (32 or 64 bits)
const maxInt = int64(^uint(0) >> 1)

// NewInMemoryStore creates a new ReadWriteSeeker in memory
func NewInMemoryStore(buf []byte) ReadWriteSeeker {
	return &inMemoryStore{
		buf: buf,
	}
}

func (s *inMemoryStore) Write(p []byte) (n int, err error) {
	idx := int(s.index)
	bufLen := len(s.buf)
	if idx != bufLen && idx <= bufLen {
		bufSlice := s.buf[:s.index]
		s.buf = bufSlice
	}

	s.buf = append(s.buf, p...)
	n = len(p)
	s.index += n

	return n, err
}

func (s *inMemoryStore) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	if s.index >= len(s.buf) {
		return 0, io.EOF
	}

	n = copy(b, s.buf[s.index:])
	s.index += n

	return n, nil
}

// Seek implements io.Seeker. Additionally, an error is returned when offset overflows
// the integer type, according to the plateform bitsize.
func (s *inMemoryStore) Seek(offset int64, whence int) (idx int64, err error) {
	if offset > maxInt {
		return 0, fmt.Errorf("offset overflow, max int: %d", maxInt)
	}
	intOffset := int(offset)

	var abs int
	switch whence {
	case io.SeekStart:
		abs = intOffset
	case io.SeekCurrent:
		abs = s.index + intOffset
	case io.SeekEnd:
		abs = len(s.buf) + intOffset
	default:
		return 0, errors.New("invalid whence")
	}

	s.index = abs
	return int64(abs), nil
}
