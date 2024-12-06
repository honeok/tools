#!/bin/bash

set -euo pipefail

## 重试次数和延迟
max_retries=5
delay=2

## 获取最新的PHP版本
LATEST_PHP_VERSION=""
for (( attempt=0; attempt < max_retries; attempt++ )); do
    LATEST_PHP_VERSION=$(curl -s https://www.php.net/releases/index.php?json | jq -r '.[].version' | grep -v '^$' | sort -V | tail -n 1) || true

    # 确保得到正确的版本
    if [[ -n "$LATEST_PHP_VERSION" && "$LATEST_PHP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        break
    fi

    echo "Failed to fetch a valid PHP version. Retrying in $delay seconds..."
    sleep "$delay"
done

if [[ -z "$LATEST_PHP_VERSION" ]]; then
    echo "Failed to fetch the latest PHP version after $max_retries attempts." >&2
    exit 1
fi

# 输出调试信息
echo "Fetched the latest PHP version: $LATEST_PHP_VERSION"

## 输出为GitHub Actions环境变量
echo "LATEST_PHP_VERSION=${LATEST_PHP_VERSION}" >> "$GITHUB_ENV"
