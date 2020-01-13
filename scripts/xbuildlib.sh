#!/bin/bash

PROJECT=e4go

echo "$PROJECT build script (c) Teserakt AG 2018-2020."
echo ""

goimports -w $PROJECT

GIT_COMMIT=$(git rev-list -1 HEAD)
GIT_TAG=$(git describe --exact-match HEAD 2>/dev/null || true)
NOW=$(date "+%Y%m%d")
BINEXT=

if [ -z "$GOOS" ]; then 
    GOOS=`uname -s | tr '[:upper:]' '[:lower:]'` 
fi
if [ -z "$GOARCH" ]; then
    GOARCH=amd64
fi

if [ -z "$OUTDIR" ]; then
    OUTDIR=bin
fi

if [[ "$GOOS" == "js" && "$GOARCH" == "wasm" ]]; then
    BINEXT=".wasm";
fi

printf "building $PROJECT:\n\tversion $NOW-$GIT_COMMIT\n\tOS $GOOS\n\tarch: $GOARCH\n"

mkdir -p $OUTDIR/${GOOS}_${GOARCH}/

printf "=> $PROJECT...\n"
CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -o $OUTDIR/${GOOS}_${GOARCH}/${PROJECT}${BINEXT} -ldflags "-X main.gitTag=$GIT_TAG -X main.gitCommit=$GIT_COMMIT -X main.buildDate=$NOW" ${PWD}


