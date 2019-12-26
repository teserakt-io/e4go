
# E4 Keygen

A simple key generator, to help create the various key types used to operate E4

## Usage

```
Usage of ./bin/e4keygen:
  -force
        force overwriting key file if it exists
  -out string
        folder path where to write the generated key (default: current folder)
  -type string
        type of the key to generate (one of "symmetric", "ed25519", "curve25519") (default "symmetric")
```

## Examples

You can use it to generate client's symmetric key:
```
$ ./bin/e4keygen -out ~/e4/keys/client1 -type symmetric
private key successfully written at ~/e4/keys/client1
```

or ed25519 private and public keys:
```
$ ./bin/e4keygen -out ~/e4/keys/client1 -type ed25519
private key successfully written at ~/e4/keys/client1
public key successfully written at ~/e4/keys/client1.pub
```

or even curve25519 keys, needed in public key mode:
```
$ ./bin/e4keygen -out ~/e4/keys/c2 -type curve25519
private key successfully written at ~/e4/keys/c2
public key successfully written at ~/e4/keys/c2.pub
```
