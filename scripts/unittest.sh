#!/bin/sh

go test . -coverprofile cover.out.tmp
cat cover.out.tmp | grep -v "c2.pb.go" | grep -v "types.go" > cover.out
rm -f cover.out.tmp
# coverage report
go tool cover -func cover.out

