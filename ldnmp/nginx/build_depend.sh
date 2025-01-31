#!/bin/bash
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

set -euo pipefail

LATEST_NGINX_VERSION=""
ZSTD_VERSION=""
CORERULESET_VERSION=""

# 重试次数和延迟
max_retries=5
delay=2

get_version() {
    local url="$1"
    local jq_filter="$2"
    local version=""
    local attempt=0

    while (( attempt < max_retries )); do
        # 获取版本的过程中出现错误尝试再次获取直到max
        version=$(curl -s --fail "$url" | jq -r "$jq_filter" 2>/dev/null) || true
        if [[ -n "$version" ]]; then
            echo "$version"
            return
        fi
        ((attempt++))
        sleep "$delay"
    done

    # 获取任一版本失败返回非0状态停止工作流
    echo "Failed to fetch version from $url" >&2
    exit 1
}

# 获取最新版本
LATEST_NGINX_VERSION=$(get_version "https://api.github.com/repos/nginx/nginx/releases/latest" '.tag_name | sub("release-"; "")')
ZSTD_VERSION=$(get_version "https://api.github.com/repos/facebook/zstd/releases/latest" '.tag_name | sub("^v"; "")')
CORERULESET_VERSION=$(get_version "https://api.github.com/repos/coreruleset/coreruleset/releases/latest" '.tag_name | sub("^v"; "")')

# 验证获取的版本是否有效
for version in "$LATEST_NGINX_VERSION" "$ZSTD_VERSION" "$CORERULESET_VERSION"; do
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
        echo "Invalid version format: $version" >&2
        exit 1
    fi
done

# 输出为GitHub Actions环境变量
{
    echo "LATEST_NGINX_VERSION=${LATEST_NGINX_VERSION}"
    echo "ZSTD_VERSION=${ZSTD_VERSION}"
    echo "CORERULESET_VERSION=${CORERULESET_VERSION}"
} >> "$GITHUB_ENV"