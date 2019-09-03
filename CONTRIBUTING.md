# Contributing

Although E4 is an in-house-developed product by Teserakt.io, it is still open-source, GPLv2-licensed software. This means you can hack it any way you want and contribute things back if you'd like to. As a software company, we focus on implementing features that are important to our products but would gladly spend some time on making E4 useful for everybody.

## Bugs, issues, feature requests

Please let us know by creating a [Github issues](https://github.com/Teserakt-io/e4common/issues) if you stumble upon a bug, have an issue or a feature request.

## Development

* We use golang version >= 1.12 for developing e4common.
* Makes sure to create new unit tests covering your code additions.
* Please create pull requests targeting the `develop` branch

## Testing

You can execute the tests by running:
```bash
./scripts/unittest.sh
```

Or using the go binary;
```bash
go test -v ./crypto
```
