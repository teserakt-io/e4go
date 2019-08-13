
# e4common

Copyright (C) Teserakt AG 2018-2019. All Rights Reserved.

This repository implements E4 in Golang, Teserakt's Secure machine-to-machine
communication protocol.

## Client usage

### Instantiating a Client

#### With symmetric key

Client instances can be created with either the `NewSymKeyClient` or
`NewSymKeyClientPretty` commands, for example you might call:
```go
    import e4 "gitlab.com/teserakt/e4common"

    var id []byte
    var key []byte
    /* get id and key from somewhere */
    client := e4.NewSymKeyClient(id, key, "/path/to/e4storage.file")
```

If you know your id and key already; alternatively you might do:
```go
    import e4 "gitlab.com/teserakt/e4common"

    name := "some client name"
    pwd := "some random password"
    /* get id and key from somewhere */
    client := e4.NewSymKeyClientPretty(name, password, "/path/to/e4storage.file")
```

If you have a human-readable client name and are deriving your encryption
key from a password. The password length must be over 16 characters.

If the client has already been persisted by running:
```go
    client.save()
```
then you can load your client from disk using the LoadClient helper:

```go
    client, err := e4.LoadClient("/path/to/e4storage.file")
    ...
```

#### With a PubKeyMaterial key

Same as for the symmetric key client, 2 constructors are available:
```go
NewPubKeyClient(id []byte, key ed25519.PrivateKey, filePath string, c2PublicKey [32]byte) (Client, error)
NewPubKeyClientPretty(name string, password string, filePath string, c2PublicKey [32]byte) (Client, error)
```

accepting the same kind of arguments than the Symmetric Key Client, with the addition of a c2PublicKey one.

Remember that in order to unprotect message, the client need to be sent the emitters public keys first.
The password is required to be over 16 characters if used.

### Processing E4 messages

You should receive messages over MQTT or Kafka using your chosen library the
usual way. Having instantiated an instance of the client, imagine that you
now also have:

    var topic String
    var message []byte

You can then unprotect the message as follows:

    plaintext, err := client.Unprotect(message, topic)
    if err != nil {
        // your error reporting here
    }

If you receive no error, the plaintext may still be nil. This happens when
E4 has processed a control message. In this case you can simply not act on
the received message - E4 has already processed it. If you want to detect this
case you can test for

    if plaintext == nil { ... }

or alternatively

    if topic == client.ReceivingTopic

which indicates a message on E4's control channel.

You should not try to parse E4's messages yourself and they are deliberately
not returned to users as this may induce security vulnerabilities.

### Sending E4 messages

If you wish to transmit a message on a topic, suppose say that you have:

    var topic String
    var message []byte

Then you may simply use the `Protect` function from the client library as
follows:

    ciphertext, err := client.Protect(message, topic)

### Handling errors

All errors should be reported and you should stop processing any plaintext or
ciphertext except in one case. If you receive `ErrTopicKeyNotFound` on a given
topic when encrypting or decrypting, it is because the client does not have
the key for this topic.

Depending on your application, your "policy" may determine what to do. You
may wish to not transmit any data, or it may be acceptable to transmit some
other plaintext message, or the original message in plaintext, depending on
your application.

If you receive this message in testing our solution, please instruct the C2
to deliver a key to the client.

## Support

You can receive support for this code by contacting team@teserakt.io.
