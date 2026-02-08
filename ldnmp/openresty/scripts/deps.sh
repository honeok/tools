#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 honeok <i@honeok.com>
#                           <honeok7@gmail.com>
#
# Thanks:
# agentzh <agentzh@gmail.com>
# Evan Wies <evan@neomantra.net>
# teddysun <i@teddysun.com>

set -eEo pipefail

# MAJOR.MINOR.PATCH
# shellcheck disable=SC2034
readonly SCRIPT_VERSION='v1.0.2'

SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

while [ "$#" -gt 0 ]; do
    case "$1" in
    --debug)
        set -x
        ;;
    --*)
        echo 2>&1 "Illegal option $1"
        ;;
    esac
    shift $(($# > 0 ? 1 : 0))
done

curl() {
    local RC

    # --fail             4xx/5xx返回非0
    # --insecure         兼容旧平台证书问题
    # --connect-timeout  连接超时保护
    # CentOS7 无法使用 --retry-connrefused 和 --retry-all-errors 因此手动 retry
    for ((i = 1; i <= 5; i++)); do
        if ! command curl --connect-timeout 10 --fail --insecure "$@"; then
            RC="$?"
            # 403 404 错误或达到重试次数
            if [ "$RC" -eq 22 ] || [ "$i" -eq 5 ]; then
                return "$RC"
            fi
            sleep 1
        else
            return 0
        fi
    done
}

# https://github.com/openresty/docker-openresty
bump_stable() {
    local OFFICIAL VAR OFFICIAL_VALUE LOCAL_VALUE

    pushd stable > /dev/null 2>&1 || exit 1

    OFFICIAL="$(curl -Ls https://raw.githubusercontent.com/openresty/docker-openresty/master/alpine/Dockerfile)"
    for VAR in \
        RESTY_OPENSSL_VERSION \
        RESTY_OPENSSL_PATCH_VERSION \
        RESTY_PCRE_VERSION \
        RESTY_PCRE_SHA256; do
        OFFICIAL_VALUE="$(grep -o "$VAR=\"[^\"]*\"" <<< "$OFFICIAL" | cut -d'"' -f2)"
        LOCAL_VALUE="$(grep -o "$VAR=\"[^\"]*\"" Dockerfile | cut -d'"' -f2)"

        if [ "$LOCAL_VALUE" != "$OFFICIAL_VALUE" ]; then
            sed -i "s#$VAR=\"$LOCAL_VALUE\"#$VAR=\"$OFFICIAL_VALUE\"#" Dockerfile
        fi
    done

    popd > /dev/null 2>&1 || exit 1
}

bump_stable_luarocks() {
    local OFFICIAL

    pushd luarocks > /dev/null 2>&1 || exit 1

    OFFICIAL="$(curl -Ls https://raw.githubusercontent.com/openresty/docker-openresty/master/alpine/Dockerfile.fat)"
    OFFICIAL_LUAROCKS_VERSION="$(grep -o 'RESTY_LUAROCKS_VERSION="[^"]*"' <<< "$OFFICIAL" | cut -d'"' -f2)"
    LOCAL_LUAROCKS_VERSION="$(grep -o 'RESTY_LUAROCKS_VERSION="[^"]*"' Dockerfile | cut -d'"' -f2)"
    if [ -n "$OFFICIAL_LUAROCKS_VERSION" ] && [ "$LOCAL_LUAROCKS_VERSION" != "$OFFICIAL_LUAROCKS_VERSION" ]; then
        sed -i "s#RESTY_LUAROCKS_VERSION=\"$LOCAL_LUAROCKS_VERSION\"#RESTY_LUAROCKS_VERSION=\"$OFFICIAL_LUAROCKS_VERSION\"#" Dockerfile
    fi

    popd > /dev/null 2>&1 || exit 1
}

bump_edge() {
    local EDGE_OPENSSL_VERSION LOCAL_OPENSSL_VERSION EDGE_PCRE2_VERSION LOCAL_PCRE2_VERSION PCRE_SHA512

    pushd edge > /dev/null 2>&1 || exit 1

    EDGE_OPENSSL_VERSION="$(curl -Ls https://api.github.com/repos/teddysun/openresty/contents/patches | grep '"name"' | cut -d '"' -f4 | grep '^openssl' | sort -V | tail -n1 | cut -d- -f2)"
    LOCAL_OPENSSL_VERSION="$(grep -o 'RESTY_OPENSSL_VERSION="[^"]*"' Dockerfile | head -n1 | cut -d'"' -f2)"
    if [ -n "$EDGE_OPENSSL_VERSION" ] && [ "$LOCAL_OPENSSL_VERSION" != "$EDGE_OPENSSL_VERSION" ]; then
        sed -i "s#RESTY_OPENSSL_VERSION=\"[^\"]*\"#RESTY_OPENSSL_VERSION=\"$EDGE_OPENSSL_VERSION\"#" Dockerfile
        sed -i "s#RESTY_OPENSSL_PATCH_VERSION=\"[^\"]*\"#RESTY_OPENSSL_PATCH_VERSION=\"$EDGE_OPENSSL_VERSION\"#" Dockerfile
    fi

    EDGE_PCRE2_VERSION="$(curl -Ls https://raw.githubusercontent.com/teddysun/openresty/main/util/build-win32.sh | sed -n 's/^PCRE=.*-\([0-9.]\+\).*/\1/p' | head -n 1)"
    LOCAL_PCRE2_VERSION="$(grep -o 'RESTY_PCRE_VERSION="[^"]*"' Dockerfile | head -n1 | cut -d'"' -f2)"
    if [ -n "$EDGE_PCRE2_VERSION" ] && [ "$LOCAL_PCRE2_VERSION" != "$EDGE_PCRE2_VERSION" ]; then
        sed -i "s#RESTY_PCRE_VERSION=\"[^\"]*\"#RESTY_PCRE_VERSION=\"$EDGE_PCRE2_VERSION\"#" Dockerfile

        # 更新SHA512
        curl -Ls -O "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$EDGE_PCRE2_VERSION/pcre2-$EDGE_PCRE2_VERSION.tar.gz"
        PCRE_SHA512="$(sha512sum "pcre2-$EDGE_PCRE2_VERSION.tar.gz" | awk '{print $1}')"
        rm -f "pcre2-$EDGE_PCRE2_VERSION.tar.gz" || exit 1
        sed -i "s#^ARG RESTY_PCRE_SHA512=\"[^\"]*\"#ARG RESTY_PCRE_SHA512=\"$PCRE_SHA512\"#" Dockerfile
    fi

    popd > /dev/null 2>&1 || exit 1
}

cd "$PARENT_DIR" > /dev/null 2>&1 || exit 1
bump_stable
bump_stable_luarocks
bump_edge
