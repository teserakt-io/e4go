#!/bin/bash
# Build Android bindings
# These two environment variable are required:
#     export ANDROID_HOME=~/Android/Sdk/
#     export ANDROID_NDK_HOME=~/Android/Sdk/ndk/21.0.6113669/
# (These are the default paths where Android Studio is installing the SDK and NDK, the version might need to be adjusted depending on your setup)

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

OUTDIR="${DIR}/../dist/bindings/android"
# List of packages to include in the generated bindings. (ie: keys is not needed)
INCLUDE_GO_PACKAGES=""

mkdir -p "${OUTDIR}" 2>/dev/null

gomobile bind -v -target android -o "${OUTDIR}/e4.aar" ${DIR}/../ ${DIR}/../crypto
