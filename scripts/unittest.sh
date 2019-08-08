#!/bin/sh

# -race increase test time a lot with crypto things, so the timeout must take that into account
go test -v -timeout 60s -race ./... -coverprofile cover.out.tmp
cat cover.out.tmp | grep -v "types.go" > cover.out
rm -f cover.out.tmp
# coverage report
go tool cover -func cover.out
