![alt text](logo.png)

- [Introduction](#introduction)
- [Using our client application](#using-our-client-application)
- [Creating a client](#creating-a-client)
  * [Symmetric-key client](#symmetric-key-client)
  * [Public-key client](#public-key-client)
  * [From a saved state](#from-a-saved-state)
- [Integration instructions](#integration-instructions)
  * [Receiving a message](#receiving-a-message)
  * [Transmitting a message](#transmitting-a-message)
  * [Handling errors](#handling-errors)
  * [Key generation](#key-generation)
  * [Bindings](#bindings)
    * [Android](#android)
- [Contributing](#contributing)
- [Security](#security)
- [Support](#support)
- [Intellectual property](#intellectual-property)

## Introduction

This repository provides the `e4` Go package, the client library for [Teserakt's E4](https://teserakt.io/e4), and end-to-end encryption and key management framework for MQTT and other publish-subscribe protocols.

The `e4` package defines a `Client` object that has a minimal interface, making its integration straightforward via the following methods:
* `ProtectMessage(payload []byte, topic string)` takes a cleartext payload to protect and the associated topic, and returns a `[]byte` that is the payload encrypted and authenticated with the topic's key.

* `Unprotect(protected []byte, topic string)` takes a protected payload and attempts to decrypt and verify it. If `topic` is the special topic reserved for control messages, then the control message is processed and the client's state updated accordingly.

Note that we talk of message *protection* instead of just *encryption* because the protection operation includes also authentication and replay defense. The *unprotection* operation thus involves decryption and additional checks, and includes the processing of control messages sent by the server.

E4's server (C2) is necessary to send control messages and manage a fleet of clients through GUIs, APIs, and automation components.
The server can for example deploy key rotation policies, grant and revoke rights, and enable forward secrecy.

Please [contact us](mailto:contact@teserakt.io) to request access to a private instance of the server, or test the limited public version.
Without the C2 server, the E4 client library can be used to protect messages using static keys, manually managed.

## Using our client application

To try E4 without writing your own application, we created a simple [interactive client application](./cmd/e4client/) that you can use in combination with our [public demo server interface](https://console.demo.teserakt.io). You can directly [download](https://github.com/teserakt-io/e4go/releases) the client's binary for your platform or build it yourself, and then follow the instructions in the client's [README](./cmd/e4client/README.md).

## Creating a client

The following instructions assume that your program imports `e4` as follows:

```go
    import e4 "github.com/teserakt-io/e4go"
```

The E4 protocol supports both symmetric key and public-key mode.
Depending on the mode, different functions should be used to instantiate a client:

### Symmetric-key client

A symmetric-key client can be created from a 16-byte identifier (type `[]byte`), a 32-byte key (type `[]byte`), and an absolute path (type `string`) to a file on the local file system, which will persistently store the client's state:

```go
    client, err := e4.NewClient(&e4.SymIDAndKey{ID: id, Key: key}, filePath)
```

A symmetric-key client can also be created from a name (`string` of arbitrary length) and a password (`string` of a least 16 characters), as follows:

```go
    client, err := e4.NewClient(&e4.SymNameAndPassword{Name: name, Password: password}, filePath)
```

The latter is a wrapper over `NewSymKeyClient()` that creates the ID by hashing `name` with SHA-3-256, and deriving a key using Argon2.

### Public-key client

A public-key client can be created from a 16-byte identifier (type `[]byte`), an Ed25519 private key (type `ed25519.PrivateKey`), an absolute file path (type `string`), and a Curve25519 public key (32-byte `[]byte`):

```go
client, err := e4.NewClient(&e4.PubIDAndKey{ID:id, Key: key, C2PubKey: c2PubKey}, filePath)
```

Compared to the symmetric-key mode, and additional argument is `c2PubKey`, the public key of the C2 server that sends control messages.

A public-key client can also be created from a name (`string` of arbitrary length) and a password (`string` of a least 16 characters), as follows:

```go
client, err := e4.NewClient(&e4.PubNameAndPassword{Name:name, Password: password, C2PubKey: c2PubKey}, filePath)
```

The Ed25519 private key is then created from a seed that is derived from the password using Argon2.
The Ed25519 public key can also be retrieved:

```go
config := &e4.PubNameAndPassword{Name:name, Password: password, C2PubKey: c2PubKey}
pubKey, err := config.PubKey()
```

### From a saved state

A client instance can be recovered using the `LoadClient()` helper, providing as argument the `filePath` of its persistent state copy:

```go
    client, err := e4.LoadClient(filePath)
```

Note that a client's state is automatically saved to the provided `filePath` every time its state changes, and therefore does not need be manually saved.

## Integration instructions

To integrate E4 into your application, the protect/unprotect logic needs be added between the network layer and the application layer when transmitting/receiving a message.

This section provides further instructions related to error handling and to the special case of control messages received from the C2 server.

Note that E4 is essentially an application security layer, therefore it processes the payload of a message (such as an MQTT payload), excluding header fields.
References to "messages" below therefore refer to payload data (or application message),as opposed to the network-level message.

### Receiving a message

Assume that you receive messages over MQTT or Kafka, and have topics and payload defined as

```go
    var topic string
    var message []byte
```

Having instantiated a client, you can then unprotect the message as follows:

```go
    plaintext, err := client.Unprotect(message, topic)
    if err != nil {
        // your error reporting here
    }
```

If you receive no error, `plaintext` may still be `nil`. This happens when E4
has processed a control message, that is, a message sent by the C2 server, for example to provision or delete a topic key.
In this case, you do not need to act on the message, since E4 has already processed it. If you want to detect this case you can test for

```go
    if len(plainText) == 0 { ... }
```

or alternatively

```go
    if client.IsReceivingTopic(topic)
```

which indicates a message on E4's control channel.
You should not have to parse E4's messages yourself.
Control messages are thus deliberately not returned to users.

If `plaintext` is not `nil` and `err` is nil, your application can proceed with the  unprotected, plaintext message.

### Transmitting a message

To protect a message to be transmitted, suppose say that you have the topic and payload defined as:

```go
    var topic string
    var message []byte
```

You can then use the `Protect` method from the client instance as follows:

```go
    protected, err := client.Protect(message, topic)
    if err != nil {
        // your error reporting here
    }
```

### Handling errors

All errors should be reported, and the `plaintext` and `protected` values discarded upon an error, *except potentially in one case*:
if you receive an `ErrTopicKeyNotFound` error from  `ProtectMessage()` or `Unprotect()`, it is because the client does not have the key for this topic.
Therefore,

* When transmitting a message, your application can either discard the message to be sent, or choose to transmit it in clear.

* When receiving a message, your application can either discard the message (for example if all messages are assumed to be encrypted in your network), or forward the message to the application (if you call `Unprotect()` for all messages yet tolerate the receiving of unencrypted messages over certain topics, which thus don't have a topic key).

In order to have the key associated to a certain topic, you must instruct the C2 to deliver said topic key to the client.

### Key generation

To ease key creation, we provide a [key generation](./cmd/e4keygen) application  that you can use to generate symmetric, Ed25519 or Curve25519 keys needed for E4 operations.
You can [download](https://github.com/teserakt-io/e4go/releases) the binary for your platform or build it yourself, and then follow the instructions in the keygen [README](./cmd/e4keygen/README.md).

Our key generator relies on Go's `crypto/rand` package, which guarantees cryptographically secure randomness across various platforms.

### Bindings

#### Android

Latest bindings for android can be downloaded from the release page.
On an environment having an Android SDK and NDK available, an Android AAR package can be generated invoking the following script:

```bash
./scripts/android_bindings.sh
```

This will generate:

- `dist/bindings/android/e4.aar`: the android package, containing compiled java class and native libraries for most common architectures
- `dist/bindings/android/e4-sources.jar`: the java source files

After importing the aar in your project, E4 client can be created and invoked in a similar way than the go version:

```kotlin
val cfg = SymNameAndPassword()
cfg.name = "deviceXYZ"
cfg.password = "secretForDeviceXYZ"

val client = E4.newClient(cfg,  cacheDir.path + "deviceXYZ.json")

// From here, messages can be protected / unprotected :
val topic = "/deviceXYZ/data";
val protectedMessage = client.protectMessage("Hello".toByteArray(Charsets.UTF_8), topic)
val unprotectedMessage = client.unprotect(protectedMessage, topic)
```


## Contributing

Before contributing, please read our [CONTRIBUTING](./CONTRIBUTING.md) guide.

## Security

To report a security vulnerability (or potential vulnerability where private discussion is preferred) see [SECURITY](./SECURITY.md).

## Support

To request support, please contact [team@teserakt.io](mailto:team@teserakt.io).

## Intellectual property

e4go is copyright (c) Teserakt AG 2018-2020, and released under Apache 2.0 License (see [LICENCE](./LICENSE)).
