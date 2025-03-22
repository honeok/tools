#!/usr/bin/env bash
#
# Description: Fetch the latest Nginx version and build its container for the LDNMP environment effortlessly.
#
# Copyright (C) 2024 - 2025 honeok <honeok@duck.com>
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

export LATEST_VERSION=""
export ZSTD_VERSION=""
export CORERULESET_VERSION=""

LATEST_VERSION=$(curl -fskL https://api.github.com/repos/nginx/nginx/releases/latest | jq -r '.tag_name | sub("release-"; "")')
ZSTD_VERSION=$(curl -fskL https://api.github.com/repos/facebook/zstd/releases/latest | jq -r '.tag_name | sub("^v"; "")')
CORERULESET_VERSION=$(curl -fskL https://api.github.com/repos/coreruleset/coreruleset/releases/latest | jq -r '.tag_name | sub("^v"; "")')

for version in "$LATEST_VERSION" "$ZSTD_VERSION" "$CORERULESET_VERSION"; do
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
        echo "Invalid version format: $version" >&2
        exit 1
    fi
done

echo "Latest NGINX version: $LATEST_VERSION"
echo "Latest ZSTD version: $ZSTD_VERSION"
echo "Latest CORERULESET version: $CORERULESET_VERSION"

{
    echo "LATEST_VERSION=${LATEST_VERSION}"
    echo "ZSTD_VERSION=${ZSTD_VERSION}"
    echo "CORERULESET_VERSION=${CORERULESET_VERSION}"
} >> "$GITHUB_ENV"