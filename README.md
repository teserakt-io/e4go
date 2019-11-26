# e4go

This Go  library provides the functions necessary to support Teserakt's E4 secure communication protocol in a client system.

## Client usage

The following examples assume that your program imports `e4go` as follows:

```go
    import e4 "github.com/teserakt-io/e4go"
```

### Instantiating a client in symmetric key mode

A new client instance can be created from a 16-byte identifier (type `[]byte`), a 32-byte key (type `[]byte`), and an absolute path (type `string`) to a file on the local file system, which will persistently store the client's  state:

```go
    client := e4.NewSymKeyClient(id, key, path)
```

A new client instance can also be created from a name (`string` or arbitrary length) and a password (`string` of a least 16 characters), instead of an identifier and a key:

```go
    client := e4.NewSymKeyClientPretty(name, password, path)
```


### Instantiating a client in public-key mode

Same as for the symmetric key client, 2 constructors are available:

```go
NewPubKeyClient(id []byte, key ed25519.PrivateKey, filePath string, c2PubKey []byte) (Client, error)
NewPubKeyClientPretty(name string, password string, filePath string, c2PubKey []byte) (Client, error)
```

accepting the same kind of arguments than the Symmetric Key Client, with the addition of a c2PubKey one.

Remember that in order to unprotect message, the client need to be sent the emitters public keys first.
The password is required to be over 16 characters if used.

### Saving and restoring a client

A client's state can be saved to the file system at any time by doing:

```go
    client.save()
```

(This save operation is automatically performed by the library when the state changes, you should not have to do it manually.)

A client instance can then be recovered from its persistent state, using the `LoadClient()` helper:

```go
    client, err := e4.LoadClient(path)
```

### Processing E4 messages

You should receive messages over MQTT or Kafka using your chosen library the
usual way. Having instantiated an instance of the client, imagine that you
now also have:

    var topic string
    var message []byte

You can then unprotect the message as follows:

    plainText, err := client.Unprotect(message, topic)
    if err != nil {
        // your error reporting here
    }

If you receive no error, the plainText may still be nil. This happens when
E4 has processed a control message. In this case you can simply not act on
the received message - E4 has already processed it. If you want to detect this
case you can test for
```go
    if len(plainText) == 0 { ... }
```
or alternatively
```go
    if client.IsReceivingTopic(topic)
```
which indicates a message on E4's control channel.

You should not try to parse E4's messages yourself and they are deliberately
not returned to users as this may induce security vulnerabilities.

### Sending E4 messages

If you wish to transmit a message on a topic, suppose say that you have:

    var topic string
    var message []byte

Then you may simply use the `Protect` function from the client library as
follows:

    cipherText, err := client.Protect(message, topic)

### Handling errors

All errors should be reported and you should stop processing any plainText or
cipherText except in one case. If you receive `ErrTopicKeyNotFound` on a given
topic when encrypting or decrypting, it is because the client does not have
the key for this topic.

Depending on your application, your "policy" may determine what to do. You
may wish to not transmit any data, or it may be acceptable to transmit some
other plainText message, or the original message in plainText, depending on
your application.

If you receive this message in testing our solution, please instruct the C2
to deliver a key to the client.

## Support

You can receive support for this code by contacting team@teserakt.io.

## Security

See [SECURITY.md](./SECURITY.md)


## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md)

