#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 honeok <i@honeok.com>

set -ex

export DEBIAN_FRONTEND=noninteractive

_exists() {
    command -v "$@" >/dev/null 2>&1
}

install_pkg() {
    for pkg in "$@"; do
        if _exists dnf; then
            dnf install -y --allowerasing "$pkg"
        elif _exists yum; then
            yum install -y "$pkg"
        elif _exists apt-get; then
            apt-get update
            apt-get install -y -q "$pkg"
        fi
    done
}

install_pkg bash curl
