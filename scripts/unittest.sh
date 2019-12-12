#!/bin/sh

set -e

if [ -z $(which golint) ]; then
    go get golang.org/x/lint/golint
fi

if [ -z $(which staticcheck) ]; then
    go get honnef.co/go/tools/cmd/staticcheck
fi

echo "Running golint..."
golint -set_exit_status ./...

echo "Running staticcheck..."
staticcheck ./...

echo "Running go test..."
# -race increase test time a lot with crypto things, so the timeout must take that into account
go test -timeout 60s -race ./... -coverprofile cover.out

# Stop here if test have failed, as coverage below will shift
# the test failures up and make it easy to miss.
if [ $? -ne 0 ]; then
    echo "FAIL - Some tests have failed."
    exit 1
fi

# coverage report
go tool cover -func cover.out
