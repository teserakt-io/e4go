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

package logger

import (
	"fmt"

	tui "github.com/marcusolsson/tui-go"
)

// Logger defines methods to log E4 client messages
type Logger interface {
	Errorf(fmtSpec string, args ...interface{})
	Error(message string)
	Printf(fmtSpec string, args ...interface{})
	Print(message string)
}

type tuiLogger struct {
	box *tui.Box
}

// NewTUILogger creates a Logger writing messages in given tui.Box
func NewTUILogger(box *tui.Box) Logger {
	return &tuiLogger{
		box: box,
	}
}

// Errorf logs errors in tui.Box, accepting arguments as fmt.Printf does.
func (l *tuiLogger) Errorf(fmtSpec string, args ...interface{}) {
	l.Error(fmt.Sprintf(fmtSpec, args...))
}

// Error logs errors in tui.Box
func (l *tuiLogger) Error(message string) {
	l.Printf("error: %s", message)
}

// Printf is similar to fmt.Printf, but writing to tui.Box instead of stdout
func (l *tuiLogger) Printf(fmtSpec string, args ...interface{}) {
	l.Print(fmt.Sprintf(fmtSpec, args...))
}

// Print wrap the given message in tui elements to display in a tui.Box
func (l *tuiLogger) Print(message string) {
	l.box.Append(tui.NewHBox(
		tui.NewPadder(1, 0, tui.NewLabel(message)),
		tui.NewSpacer(),
	))
}
