# E4 Go Client

A command-line application to interact with Teserakt's key management service [E4](https://teserakt.io/#e4)

## Usage

```
Usage of ./bin/e4client:
  -broker string
        ip:port of the MQTT broker
  -c2PubKey string
        path to the c2 public key. Required with -pubkey
  -name string
        The client identifier
  -password string
        The client password, over 16 characters
  -pubkey
        Enable public key mode
```

## Getting started using the e4-demo environment

Choose your own deviceID and a password (min 16 characters), and launch the client:
```
./bin/e4client -name deviceID -password superSecretDevicePassword -broker mqtt.teserakt.io:1883
```

This will start an E4 interactive shell, with commands to subscribe to topics and send protected / unprotected messages.

```
E4 Client Interactive Shell
Type help for available commands
---------------------------------
> help
Available commands:
  help                            show this help
  print-key <password>            helper to derivate a key from a password and print it as a 32 bytes hex string
  e4msg <topicName> <message>     send a protected message on a topic
  clearmsg <topicName> <message>  send an unprotected message on a topic
  subscribe <topicName>           subscribe to a topic
  unsubscribe <topicName>         unsubscribe from a topic
  exit                            exit the application
```

First, print the key and register the device on the web UI. Repeat the password provided when launching the client to obtain the actual key:

```
> print-key superSecretDevicePassword
device key: a83d896e7513e929cf63206e9c07629a441d64fb187cae0501f28786ecb8a55d
```

Then head over `https://console.demo.teserakt.io/clients` and add your client here, providing the same name you used to start it and the above key.

Now, subscribe to a topic:
```
> subscribe demoTopic
success subscribing to topic 'demoTopic'
```

And head back to the web UI to create the topic if it doesn't exists yet, and bind your client on it.

And you're all set, you can now send and read messages on any topic your device is bound to.

```
> e4msg demoTopic test
received protected message on topic demoTopic: test
protected message has been published on topic demoTopic
> e4msg anotherTopic test
failed to protect message: topic key not found
```
