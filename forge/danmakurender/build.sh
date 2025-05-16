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

# prepare running environment.
mv -f DanmakuRender/* .
mv -f biliup tools/
rm -rf DanmakuRender

# clean up the extra docs files in danmakurender repository.
rm -f Dockerfile -- *.md
rm -rf docs

\cp -rf configs /opt/configs