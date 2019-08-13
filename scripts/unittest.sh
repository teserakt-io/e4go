#!/bin/sh

# -race increase test time a lot with crypto things, so the timeout must take that into account
go test -timeout 60s -race ./... -coverprofile cover.out.tmp

# Stop here if test have failed, as coverage below will shift
# the test failures up and make it easy to miss.
if [ $? -ne 0 ]; then
    echo "FAIL - Some test have failed."
    exit 1
fi

cat cover.out.tmp | grep -v "types.go" > cover.out
rm -f cover.out.tmp
# coverage report
go tool cover -func cover.out
