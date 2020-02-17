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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	tui "github.com/marcusolsson/tui-go"

	e4 "github.com/teserakt-io/e4go"
	e4crypto "github.com/teserakt-io/e4go/crypto"

	"github.com/teserakt-io/e4go/cmd/e4client/commands"
	"github.com/teserakt-io/e4go/cmd/e4client/logger"
)

func main() {
	var name string
	var password string
	var pubKeyMode bool
	var c2PubKeyPath string
	var broker string

	flag.StringVar(&name, "name", "", "The client identifier")
	flag.StringVar(&password, "password", "", "The client password, over 16 characters")
	flag.BoolVar(&pubKeyMode, "pubkey", false, "Enable public key mode")
	flag.StringVar(&c2PubKeyPath, "c2PubKey", "", "path to the c2 curve25519 public key. Required with -pubkey")
	flag.StringVar(&broker, "broker", "", "ip:port of the MQTT broker")
	flag.Parse()

	log.SetFlags(0)

	if len(name) == 0 {
		flag.Usage()
		log.Fatal("\n-name is required")
	}

	if len(password) < 16 {
		flag.Usage()
		log.Fatal("\n-password is required and must contains at least 16 characters")
	}

	if len(broker) == 0 {
		flag.Usage()
		log.Fatal("\n-broker is required")
	}

	if pubKeyMode && len(c2PubKeyPath) == 0 {
		flag.Usage()
		log.Fatal("\n-c2pubkey is required")
	}

	var c2PubKey []byte
	var err error

	if len(c2PubKeyPath) != 0 {
		if c2PubKey, err = ioutil.ReadFile(c2PubKeyPath); err != nil {
			log.Fatalf("failed to read key from %s: %v\n", c2PubKeyPath, err)
		}
	}

	history := tui.NewVBox()
	historyScroll := tui.NewScrollArea(history)
	historyScroll.SetAutoscrollToBottom(true)

	logger := logger.NewTUILogger(history)

	e4Client, err := loadOrCreateClient(name, password, pubKeyMode, c2PubKey)
	if err != nil {
		log.Fatalf("Failed to load or create E4 client: %v\n", err)
	}
	logger.Printf("E4 client '%s' initialized\n", name)

	mqttClient, err := initMQTT(broker, name)
	if err != nil {
		log.Fatalf("Failed to init mqtt client: %v\n", err)
	}
	logger.Printf("Connected to MQTT broker %s\n", broker)

	if err := subscribeToE4ControlTopic(logger, e4Client, mqttClient); err != nil {
		log.Fatalf("Failed to subscribe to e4 client control topic: %v\n", err)
	}
	logger.Printf("Subscribed to MQTT device control topic %s\n", e4Client.GetReceivingTopic())

	logger.Print("---------------------------------")
	logger.Print("E4 Client Interactive Shell")
	logger.Print("Type help for available commands")
	logger.Print("---------------------------------")

	historyBox := tui.NewVBox(historyScroll)
	historyBox.SetBorder(true)

	input := tui.NewEntry()
	input.SetFocused(true)
	input.SetSizePolicy(tui.Expanding, tui.Maximum)

	inputBox := tui.NewHBox(input)
	inputBox.SetBorder(true)
	inputBox.SetSizePolicy(tui.Expanding, tui.Maximum)

	chat := tui.NewVBox(historyBox, inputBox)
	chat.SetSizePolicy(tui.Expanding, tui.Expanding)

	ui, err := tui.New(chat)
	if err != nil {
		log.Fatalf("Failed to init tui: %v\n", err)
	}

	commands := []*commands.Command{
		commands.PrintKeyCommand(logger, pubKeyMode),
		commands.SendProtectedMessageCommand(e4Client, mqttClient, logger),
		commands.SendUnprotectedMessageCommand(e4Client, mqttClient, logger),
		commands.SubscribeTopicCommand(e4Client, mqttClient, logger),
		commands.UnsubscribeTopicCommand(e4Client, mqttClient, logger),
		commands.ExitCommand(ui),
	}

	input.OnSubmit(func(e *tui.Entry) {
		logger.Printf("> %s", e.Text())

		args := strings.Split(e.Text(), " ")
		if len(args) == 0 {
			return
		}

		command := args[0]
		switch command {
		case "help":
			pad := len("help")
			for _, cmd := range commands {
				helpLength := len(cmd.Name) + len(cmd.ArgsHelp)
				if helpLength > pad {
					pad = helpLength
				}
			}

			logger.Print("Available commands:")
			logger.Printf("  %s  %s %s", "help", strings.Repeat(" ", pad-len("help")), "show this help")
			for _, cmd := range commands {
				logger.Printf("  %s %s %s %s", cmd.Name, cmd.ArgsHelp, strings.Repeat(" ", pad-len(cmd.Name)-len(cmd.ArgsHelp)), cmd.Help)
			}
			input.SetText("")
		default:
			for _, cmd := range commands {
				if cmd.Name == command {
					cmd.Func(args[1:])
					input.SetText("")
					return
				}
			}

			logger.Printf("Unknown command")
			input.SetText("")
		}
	})

	ui.SetKeybinding("Esc", func() { ui.Quit() })
	ui.SetKeybinding("Tab", func() {
		cmdNames := []string{"help"}
		for _, cmd := range commands {
			cmdNames = append(cmdNames, cmd.Name)
		}

		var matches []string
		re := regexp.MustCompile(fmt.Sprintf(`^%s`, input.Text()))
		for _, name := range cmdNames {
			if re.MatchString(name) {
				matches = append(matches, name)
			}
		}

		if len(matches) == 1 {
			input.SetText(matches[0])
		} else {
			if len(matches) == 0 {
				return
			}

			logger.Printf("suggestions:\n%s", strings.Join(matches, " "))

			// Autocomplete as much as we can
			if len(matches) > 1 {
				shortest := matches[0]
				for _, m := range matches {
					if len(m) < len(shortest) {
						shortest = m
					}
				}

				for i := len(input.Text()); i < len(shortest); i++ {
					for _, m := range matches {
						if m[i] != shortest[i] {
							if i > 0 {
								input.SetText(input.Text() + shortest[len(input.Text()):i])
							}

							return
						}
					}
				}
			}
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			select {
			case <-time.After(500 * time.Millisecond):
				ui.Repaint()
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := ui.Run(); err != nil {
		log.Fatal(err)
	}
}

func loadOrCreateClient(name, password string, pubKeyMode bool, c2PubKey e4crypto.Curve25519PublicKey) (e4.Client, error) {
	var e4Client e4.Client

	savedClientPath := fmt.Sprintf("./%s.json", name)
	dstFile, err := os.OpenFile(savedClientPath, os.O_RDWR, 0600)
	switch {
	case err == nil:
		e4Client, err = e4.LoadClient(dstFile)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Loaded client from %s\n", savedClientPath)

	default:
		if !os.IsNotExist(err) {
			fmt.Printf("Failed to load client from file %s: %v\n", savedClientPath, err)
			os.Exit(1)
		}

		dstFile, err := os.OpenFile(savedClientPath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			fmt.Printf("Failed to create client save file %s: %v\n", savedClientPath, err)
			os.Exit(1)
		}

		var config e4.ClientConfig
		if pubKeyMode {
			config = &e4.PubNameAndPassword{Name: name, Password: password, C2PubKey: c2PubKey}
		} else {
			config = &e4.SymNameAndPassword{Name: name, Password: password}
		}

		e4Client, err = e4.NewClient(config, dstFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create E4 client: %v", err)
		}
	}

	return e4Client, nil
}

func initMQTT(broker string, name string) (mqtt.Client, error) {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID(name)
	opts.SetCleanSession(true)

	mqttClient := mqtt.NewClient(opts)

	token := mqttClient.Connect()
	if err := token.Error(); err != nil {
		return nil, err
	}

	if !token.WaitTimeout(time.Second) {
		return nil, errors.New("got mqtt timeout while connecting to mqtt broker")
	}

	return mqttClient, nil
}

// subscribeToE4ControlTopic will subscribe to the e4 client control topic on MQTT broker,
// allowing it to receives and process commands from the C2 server.
func subscribeToE4ControlTopic(logger logger.Logger, e4Client e4.Client, mqttClient mqtt.Client) error {
	token := mqttClient.Subscribe(e4Client.GetReceivingTopic(), 2, func(client mqtt.Client, msg mqtt.Message) {
		_, err := e4Client.Unprotect(msg.Payload(), e4Client.GetReceivingTopic())
		if err != nil {
			logger.Errorf("E4 unprotect command error: %v", err)
			return
		}

		logger.Print("success processing E4 command")
	})

	if err := token.Error(); err != nil {
		return err
	}

	if !token.WaitTimeout(time.Second) {
		return errors.New("got mqtt timeout while subscribing to E4 control topic")
	}

	return nil
}
