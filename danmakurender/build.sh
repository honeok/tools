#!/usr/bin/env sh
#
# Description: Script for installing the necessary dependencies to build the containerized version of DanmakuRender.
#
# Copyright (c) 2025 honeok <honeok@duck.com>
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

set -eux

pkg_install() {
    for pkg in "$@"; do
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y "$pkg"
        elif command -v yum >/dev/null 2>&1; then
            yum install -y "$pkg"
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get install -y -q "$pkg"
        elif command -v apk >/dev/null 2>&1; then
            apk add --no-cache "$pkg"
        else
            printf 'The package manager is not supported.\n' >&2; exit 1
        fi
    done
}

command -v curl >/dev/null 2>&1 || pkg_install curl

DANMAKU_TAG=$(curl -fsL "https://api.github.com/repos/SmallPeaches/DanmakuRender/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
if ! git clone --branch "$DANMAKU_TAG" https://github.com/SmallPeaches/DanmakuRender.git; then
    printf 'Error: Unable to obtain DanmakuRender source code!\n' >&2; exit 1
fi

BILIUPRS_VERSION=$(curl -fsL "https://api.github.com/repos/biliup/biliup-rs/releases/latest" | awk -F '["v]' '/tag_name/{print $5}')
readonly BILIUPRS_VERSION
[ -z "$BILIUPRS_VERSION" ] && { printf 'Error: Unable to obtain biliup-rs version!\n' >&2; exit 1; }

case "$(uname -m)" in
    x86_64 | amd64)
        BILIUPRS_FRAMEWORK='x86_64'
    ;;
    armv8* | arm64 | aarch64)
        BILIUPRS_FRAMEWORK='aarch64'
    ;;
    *)
        printf "Error: unsupported architecture: %s\n" "$(uname -m)" >&2; exit 1
    ;;
esac

if ! curl -fsL -O "https://github.com/biliup/biliup-rs/releases/download/v$BILIUPRS_VERSION/biliupR-v$BILIUPRS_VERSION-$BILIUPRS_FRAMEWORK-linux.tar.xz"; then
    printf 'Error: Failed to download biliup-rs, please check the network!\n' >&2; exit 1
fi

# prepare running environment.
mv -f DanmakuRender/* .
rm -rf DanmakuRender
tar xf "biliupR-v$BILIUPRS_VERSION-$BILIUPRS_FRAMEWORK-linux.tar.xz" --strip-components=1
rm -f "biliupR-v$BILIUPRS_VERSION-$BILIUPRS_FRAMEWORK-linux.tar.xz"
mv -f biliup tools/

# clean up the extra docs files in danmakurender repository.
rm -f Dockerfile -- *.md
rm -rf docs

\cp -rf configs /opt/configs