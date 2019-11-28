# Contributing

e4go is maintained by [Teserakt AG](https://teserakt.io) and its team:

* [@daeMOn63 ](https://github.com/daeMOn63) (Flavien Binet)
* [@diagprov](https://github.com/diagprov) (Antony Vennard)
* [@odeke-em](https://github.com/odeke-em) (Emmanuel Odeke)
* [@veorq](https://github.com/veorq) (JP Aumasson)

We welcome and encourage third-party contributions to e4go, be it reports of issues encountered while using the software, suggestions of new features, or proposals of patches.

## Bug reports

Bugs, problems, and feature requests should be reported on [GitHub Issues](https://github.com/teserakt-io/e4go/issues).

If you report a bug, please:

* Check that it's not already reported in the [GitHub Issues](https://github.com/teserakt-io/e4go/issues).
* Provide information to help us diagnose and ideally reproduce the bug.

We appreciate feature requests, however we cannot guarantee that all feature requested will be added to e4go.

## Patches

We enraouge you to fix a bug or implement a new feature via a [GitHub Pull request](https://github.com/teserakt-io/e4go/pulls), preferably after creating a related issue and referring it in the PR.

If you contribute code and submit a patch, please note the following:

* We use Go version >= 1.13 for developing e4go.
* Pull requests should target the `develop` branch.
* Follow the established Go [coding conventions](https://golang.org/doc/effective_go.html)

Also please make sure to create new unit tests covering your code additions. You can execute the tests by running:

```bash
./scripts/unittest.sh
```

or using the go binary;

```bash
go test -v ./crypto
```

All third-party contributions will be recognized in the list of contributors.

## House rules

When posting on discussion threads, please be respectful and civil, avoid (passive-)agressive tone, and try to communicate clearly and succinctly. This is usually better for everyone :-)
