
# e4common

Copyright (C) Teserakt AG 2018-2019. All Rights Reserved.

This repository implements E4 in Golang, Teserakt's Secure machine-to-machine 
communication protocol.

## Client usage

### Instantiating a Client

Client instances can be created with either the `NewClient` or 
`NewClientPretty` commands, for example you might call:

    import e4 "gitlab.com/teserakt/e4common"

    var id []byte
    var key []byte
    /* get id and key from somewhere */
    client := e4.NewClient(id, key, "/path/to/e4storage.file")

If you know your id and key already; alternatively you might do:

    import e4 "gitlab.com/teserakt/e4common"

    name := "some client name"
    pwd := "some password"
    /* get id and key from somewhere */
    client := e4.NewClientPretty(name, password, "/path/to/e4storage.file")

If you have a human-readable client name and are deriving your encryption 
key from a password.

If the client has already been persisted by running:

    client.save()

then you can load your client from disk using the LoadClient helper:


    client, err := e4.LoadClient("/path/to/e4storage.file")
    ...

### Processing E4 messages

You should receive messages over MQTT or Kafka using your chosen library the 
usual way. Having instantiated an instance of the client, imagine that you 
now also have:

    var topic String
    var message []byte

You can then unprotect the message as follows:

    plaintext, err := client.Unprotect(message, topic)

You should then insert the following check into your code to ensure that E4 
messages can be processed:

    if topic == client.ReceivingTopic {
        command, err := cli.E4.ProcessCommand([]byte(plaintext))
        if err != nil {
            // error reporting as you would normally do it
        }

        // stop processing plaintext here, even on success
    }

Otherwise, assuming no error occurred and the topic is not the receiving topic, 
you can continue to process the plaintext

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
