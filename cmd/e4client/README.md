# E4 Go Client

We provide a simple command-line application to interact with Teserakt's key management server [E4](https://teserakt.io/e4.html).

You can [download](https://github.com/teserakt-io/e4go/releases) the binary for your platform or build it yourself.

The program takes the following arguments (note that it does not need to know the server host address, this is the magic of E4):
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

## Getting started using the demo environment

We describe how to use the client application in combination with our public demo server instance.
Keep in mind that the server is only for demonstration purposes, and is operated by Teserakt without any guarantee.
Also note that, since the demo platform is public and registration-free, anyone will see your client in the list of devices, and therefore anyone could remove it from the platform, for example.

### 1. Create a client instance

Choose your own deviceID and a password (at least 16 characters), and launch the client:
```
./bin/e4client -name deviceID -password superSecretDevicePassword -broker mqtt.demo.teserakt.io:1883
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

### 2. Register your client on the demo server

First, use the `print-key` command to obtain your device key from its password (in our example, the password is "superSecretDevicePassword"):

```
> print-key superSecretDevicePassword
device key: a83d896e7513e929cf63206e9c07629a441d64fb187cae0501f28786ecb8a55d
```

Then head over to `https://console.demo.teserakt.io/clients`, click on "ADD CLIENT", and add your deviceID and the key obtained in the previous step.

### 3. Subscribe to a topic and generate a key for it

In this step, the client will create a new topic, tell the server that messages sent with this topic are to be protected, and tell the server to grant encryption/decryption rights to our device.

For example, in a real application the topic might be the type of data sent such as telemetry data, the identifier of a subgroup of devices, a secrecy classification level, or the identifier of an  ephemeral conversation between two or more devices.

Using the topic "demoTopic" as an example, first use the client interactive shell to subscribe to the topic, as follows:

```
> subscribe demoTopic
success subscribing to topic 'demoTopic'
```

Then go to `https://console.demo.teserakt.io/topics`, click on "ADD TOPIC", and add your "demoTopic".
This time, no need to generate the key, as the server takes care of it.

To authorize your client to encrypt and decrypt demoTopic messages, click the "Edit" action pictogram next to the topic created in the list, and add your device. You can also add the topic from the "Edit" menu of the client.

### 4. Send and receive messages

And you're all set, you can now send and read messages on any topic your device is bound to, using the `e4msg` command:

```
> e4msg demoTopic test
received protected message on topic demoTopic: test
protected message has been published on topic demoTopic
```

Using similar operations, you can now create multiple client instances and multiple topics, and use the web UI to manage access rights to protected topics.