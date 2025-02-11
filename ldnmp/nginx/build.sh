#!/usr/bin/env bash
#
# Description: Automatically fetch the latest Nginx version and build the Nginx container for the LDNMP environment.
#
# Copyright (C) 2024 - 2025 honeok <honeok@duck.com>
#
# License Information:
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License, version 3 or later.
#
# This program is distributed WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.

set \
    -o errexit \
    -o nounset \
    -o pipefail

LATEST_NGINX_VERSION=""
ZSTD_VERSION=""
CORERULESET_VERSION=""

install() {
    if [ "$#" -eq 0 ]; then
        echo "ERROR: No package parameters provided!"
        return 1
    fi

    for package in "$@"; do
        if ! command -v "$package" >/dev/null 2>&1; then
            echo "INFO: Installing $package"
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y epel-release
                dnf install -y "$package"
            elif command -v yum >/dev/null 2>&1; then
                yum install -y epel-release
                yum install -y "$package"
            elif command -v apt >/dev/null 2>&1; then
                apt install -y "$package"
            elif command -v apt-get >/dev/null 2>&1; then
                apt-get install -y "$package"
            else
                echo "ERROR: Unknown package manager!"
                return 1
            fi
        else
            echo "INFO: $package is already installed!"
        fi
    done
    return 0
}

install jq curl

LATEST_NGINX_VERSION=$(curl -s https://api.github.com/repos/nginx/nginx/releases/latest | jq -r '.tag_name | sub("release-"; "")')
ZSTD_VERSION=$(curl -s https://api.github.com/repos/facebook/zstd/releases/latest | jq -r '.tag_name | sub("^v"; "")')
CORERULESET_VERSION=$(curl -s https://api.github.com/repos/coreruleset/coreruleset/releases/latest | jq -r '.tag_name | sub("^v"; "")')

for version in "$LATEST_NGINX_VERSION" "$ZSTD_VERSION" "$CORERULESET_VERSION"; do
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
        echo "Invalid version format: $version" >&2
        exit 1
    fi
done

echo "Latest NGINX version: $LATEST_NGINX_VERSION"
echo "Latest ZSTD version: $ZSTD_VERSION"
echo "Latest CORERULESET version: $CORERULESET_VERSION"

{
    echo "LATEST_NGINX_VERSION=${LATEST_NGINX_VERSION}"
    echo "ZSTD_VERSION=${ZSTD_VERSION}"
    echo "CORERULESET_VERSION=${CORERULESET_VERSION}"
} >> "$GITHUB_ENV"