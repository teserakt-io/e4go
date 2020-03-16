#!/bin/bash
# Build Android bindings
# These two environment variable are required:
#     export ANDROID_HOME=~/Android/Sdk/
#     export ANDROID_NDK_HOME=~/Android/Sdk/ndk/21.0.6113669/
# (These are the default paths where Android Studio is installing the SDK and NDK, the version might need to be adjusted depending on your setup)
# A version string can be appended to the output files by specifying a E4VERSION environment variable:
#     E4VERSION=v1.1.0 ./scripts/android_bindings.sh


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

OUTDIR="${DIR}/../dist/bindings/android"
# List of packages to include in the generated bindings. (ie: keys is not needed)
INCLUDE_GO_PACKAGES=""

mkdir -p "${OUTDIR}" 2>/dev/null

gomobile bind -v -target android -o "${OUTDIR}/e4.aar" -javapkg io.teserakt ${DIR}/../ ${DIR}/../crypto

if [ ! -z "${E4VERSION}" ]; then
    mv "${OUTDIR}/e4.aar" "${OUTDIR}/e4_${E4VERSION}.aar"
    mv "${OUTDIR}/e4-sources.jar" "${OUTDIR}/e4-sources_${E4VERSION}.jar"
fi

# gomobile will mess up the go.mod file when running, tidying restore it to the appropriate state
cd "${DIR}/../" && go mod tidy && cd -
