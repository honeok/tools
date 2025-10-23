#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Description: This script is used to build and publish the latest version of openresty integrated luarocks image.
# Copyright (c) 2025 honeok <i@honeok.com>

set -eE

RESTY_VERSION="$(wget -qO- https://api.github.com/repos/openresty/openresty/tags | grep '"name":' | sed -E 's/.*"name": *"([^"]+)".*/\1/' | sort -rV | head -n1 | sed 's/v//')"

docker buildx build \
    --no-cache \
    --progress=plain \
    --platform linux/amd64,linux/arm64 \
    --tag honeok/openresty:"$RESTY_VERSION-alpine-fat" \
    --push \
    . && echo 2>&1 "build complete!"
