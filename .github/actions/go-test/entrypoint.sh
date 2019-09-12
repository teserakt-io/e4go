#!/bin/bash

set -e

# Create netrc file with given username and access token so go get could authenticate to
# github and fetch private repositories.
if [ ! -z "${CI_USERNAME}" ] && [ ! -z "${CI_ACCESS_TOKEN}" ]; then
    echo "machine github.com login ${CI_USERNAME} password ${CI_ACCESS_TOKEN}" > ~/.netrc
else
    echo "No CI_USERNAME or CI_ACCESS_TOKEN defined, skipping authentication."
fi


RACE=""
if [ ! -e "{$INPUT_RACE}" ]; then
    RACE="-race"
fi

go test -timeout ${INPUT_TIMEOUT} ${RACE} ./... -coverprofile cover.out

# coverage report
go tool cover -func cover.out
