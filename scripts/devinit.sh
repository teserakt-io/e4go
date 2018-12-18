#!/bin/sh

GIT_VERSION=$(git --version | cut -d" " -f3)
GIT_REQUIRED_VERSION=2.9.0

if [ "$(printf '%s\n' "$GIT_REQUIRED_VERSION" "$GIT_VERSION" | sort -V | head -n1)" = "$GIT_REQUIRED_VERSION" ]; then 
    echo "GIT >= 2.9, installing .githooks directory"
    git config core.hooksPath .githooks
else
    echo "Copying githooks to .git"
    #find .git/hooks -type l -exec rm {} \; && find .githooks -type f -exec ln -sf ../../{} .git/hooks/ \;
fi
