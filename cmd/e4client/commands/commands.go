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

package commands

import (
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	tui "github.com/marcusolsson/tui-go"

	e4 "github.com/teserakt-io/e4go"
	e4crypto "github.com/teserakt-io/e4go/crypto"

	"github.com/teserakt-io/e4go/cmd/e4client/logger"
)

// Command defines a E4 Client command
type Command struct {
	Name     string
	Help     string
	ArgsHelp string
	Func     func([]string)
}

// SubscribeTopicCommand creates a command to subscribe to MQTT topics
func SubscribeTopicCommand(e4Client e4.Client, mqttClient mqtt.Client, l logger.Logger) *Command {
	return &Command{
		Name:     "subscribe",
		Help:     "subscribe to a topic",
		ArgsHelp: "<topicName>",
		Func: func(args []string) {
			if len(args) != 1 {
				l.Print("Usage: subscribe <topicName>")
				return
			}

			token := mqttClient.Subscribe(args[0], 2, func(client mqtt.Client, msg mqtt.Message) {
				unprotected, err := e4Client.Unprotect(msg.Payload(), msg.Topic())
				if err != nil {
					l.Errorf("failed to unprotect E4 message on topic %s: %v", msg.Topic(), err)
					return
				}

				l.Printf("< [%s] %s", msg.Topic(), unprotected)
			})

			if err := token.Error(); err != nil {
				l.Errorf("got mqtt subscribe error: %v", err)
				return
			}

			if !token.WaitTimeout(time.Second) {
				l.Error("got timeout waiting for mqtt reply")
				return
			}

			l.Printf("success subscribing to topic '%s'", args[0])
		},
	}
}

// UnsubscribeTopicCommand creates a command to unsubscribe from MQTT topics
func UnsubscribeTopicCommand(e4Client e4.Client, mqttClient mqtt.Client, l logger.Logger) *Command {
	return &Command{
		Name:     "unsubscribe",
		Help:     "unsubscribe from a topic",
		ArgsHelp: "<topicName>",
		Func: func(args []string) {
			if len(args) != 1 {
				l.Print("Usage: unsubscribe <topicName>")
				return
			}

			token := mqttClient.Unsubscribe(args[0])

			if err := token.Error(); err != nil {
				l.Errorf("got mqtt subscribe error: %v", err)
				return
			}

			if !token.WaitTimeout(time.Second) {
				l.Error("got timeout waiting for mqtt reply")
				return
			}

			l.Printf("success unsubscribing from topic '%s'", args[0])
		},
	}
}

// SendProtectedMessageCommand creates a command to send a protected message
func SendProtectedMessageCommand(e4Client e4.Client, mqttClient mqtt.Client, l logger.Logger) *Command {
	return &Command{
		Name:     "e4msg",
		Help:     "send a protected message on a topic",
		ArgsHelp: "<topicName> <message>",
		Func: func(args []string) {
			if len(args) < 2 {
				l.Print("Usage: e4msg <topicName> <message>")
				return
			}

			topic := args[0]
			message := strings.Join(args[1:], " ")

			payload, err := e4Client.ProtectMessage([]byte(message), topic)
			if err != nil {
				l.Errorf("failed to protect message: %v", err)
				return
			}

			token := mqttClient.Publish(topic, 2, true, payload)
			if err := token.Error(); err != nil {
				l.Errorf("got mqtt publish error: %v", err)
				return
			}
			if !token.WaitTimeout(time.Second) {
				l.Errorf("got timeout waiting for mqtt reply")
				return
			}

			l.Printf("protected message has been published on topic %s", topic)
		},
	}
}

// SendUnprotectedMessageCommand creates a command to send an unprotected message
func SendUnprotectedMessageCommand(e4Client e4.Client, mqttClient mqtt.Client, l logger.Logger) *Command {
	return &Command{
		Name:     "clearmsg",
		Help:     "send an unprotected message on a topic",
		ArgsHelp: "<topicName> <message>",
		Func: func(args []string) {
			if len(args) < 2 {
				l.Print("Usage: clearmsg <topicName> <message>")
				return
			}

			topic := args[0]
			message := strings.Join(args[1:], " ")

			token := mqttClient.Publish(topic, 2, true, message)
			if err := token.Error(); err != nil {
				l.Errorf("got mqtt publish error: %v", err)
				return
			}
			if !token.WaitTimeout(time.Second) {
				l.Error("got timeout waiting for mqtt reply")
				return
			}

			l.Printf("message has been published on topic %s", topic)
		},
	}
}

// PrintKeyCommand print out a hex string key derived from a password
func PrintKeyCommand(l logger.Logger) *Command {
	return &Command{
		Name:     "print-key",
		Help:     "helper derivating a key from a password and print it as a 32 bytes hex string",
		ArgsHelp: "<password>",
		Func: func(args []string) {
			if len(args) != 1 {
				l.Print("Usage: print-key <password>")
				return
			}

			key, err := e4crypto.DeriveSymKey(args[0])
			if err != nil {
				l.Printf("failed to generate key: %v", err)
				return
			}

			l.Printf("key: %x", key)
		},
	}
}

// ExitCommand exit the program
func ExitCommand(ui tui.UI) *Command {
	return &Command{
		Name: "exit",
		Help: "exit the application",
		Func: func(args []string) {
			ui.Quit()
		},
	}
}
