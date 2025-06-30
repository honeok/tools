#!/usr/bin/env bash
#
# Description: This script is used to install or update to the latest go version.
#
# Copyright (c) 2025 honeok <honeok@disroot.org>
#
# SPDX-License-Identifier: MIT

_red() { printf "\033[91m%s\033[0m\n" "$*"; }
_green() { printf "\033[92m%s\033[0m\n" "$*"; }
_yellow() { printf "\033[93m%s\033[0m\n" "$*"; }
_err_msg() { printf "\033[41m\033[1mError\033[0m %s\n" "$*"; }
_suc_msg() { printf "\033[42m\033[1mSuccess\033[0m %s\n" "$*"; }
_info_msg() { printf "\033[43m\033[1mInfo\033[0m %s\n" "$*"; }

# 各变量默认值
GITHUB_PROXY='https://files.m.daocloud.io/'
RANDOM_CHAR="$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 5)"
TEMP_DIR="/tmp/go_$RANDOM_CHAR"

# 设置系统utf-8语言环境
UTF8_LOCALE="$(locale -a 2>/dev/null | grep -iEm1 "UTF-8|utf8")"
[ -n "$UTF8_LOCALE" ] && export LC_ALL="$UTF8_LOCALE" LANG="$UTF8_LOCALE" LANGUAGE="$UTF8_LOCALE"

# 打印错误信息并退出
die() {
    _err_msg >&2 "$(_red "$@")"; exit 1
}

mkdir -p "$TEMP_DIR" >/dev/null 2>&1
if [ "$(cd -P -- "$(dirname -- "$0")" && pwd -P)" != "$TEMP_DIR" ]; then
    cd "$TEMP_DIR" >/dev/null 2>&1 || die "Can't access temporary working directory."
fi

# 终止信号捕获退出前清理操作
_exit() {
    local ERR_CODE="$?"
    rm -rf "$TEMP_DIR" >/dev/null 2>&1
    exit "$ERR_CODE"
}

# 终止信号捕获
trap '_exit' SIGINT SIGQUIT SIGTERM EXIT

clrscr() {
    ([ -t 1 ] && tput clear 2>/dev/null) || echo -e "\033[2J\033[H" || clear
}

_exists() {
    local _CMD="$1"
    if type "$_CMD" >/dev/null 2>&1; then return 0;
    elif command -v "$_CMD" >/dev/null 2>&1; then return 0;
    elif which "$_CMD" >/dev/null 2>&1; then return 0;
    else return 1;
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
}

check_cdn() {
    # https://danwin1210.de/github-ipv6-proxy.php
    ipv6_proxy() {
        local -a HOST_ENTRIES
        command cp -f /etc/hosts{,.bak}
        HOST_ENTRIES=(
            "2a01:4f8:c010:d56::2 github.com"
            "2a01:4f8:c010:d56::3 api.github.com"
            "2a01:4f8:c010:d56::4 codeload.github.com"
            "2a01:4f8:c010:d56::5 objects.githubusercontent.com"
            "2a01:4f8:c010:d56::6 ghcr.io"
            "2a01:4f8:c010:d56::7 pkg.github.com npm.pkg.github.com maven.pkg.github.com nuget.pkg.github.com rubygems.pkg.github.com"
            "2a01:4f8:c010:d56::8 uploads.github.com"
        )
        for ENTRY in "${HOST_ENTRIES[@]}"; do
            echo "$ENTRY" >> /etc/hosts
        done
    }
    COUNTRY="$(curl --max-time 5 --insecure --location --silent "https://www.qualcomm.cn/cdn-cgi/trace" | grep -i '^loc=' | cut -d'=' -f2 | grep .)"
    IPV4_ADDRESS="$(curl --max-time 5 --insecure --location --silent --ipv4 "https://www.qualcomm.cn/cdn-cgi/trace" | grep -i '^ip=' | cut -d'=' -f2 | grep .)"
    IPV6_ADDRESS="$(curl --max-time 5 --insecure --location --silent --ipv6 "https://www.qualcomm.cn/cdn-cgi/trace" | grep -i '^ip=' | cut -d'=' -f2 | grep .)"
    if [ "$COUNTRY" != "CN" ] && [ -n "$IPV4_ADDRESS" ]; then
        unset GITHUB_PROXY
    elif [ "$COUNTRY" != "CN" ] && [ -z "$IPV4_ADDRESS" ] && [ -n "$IPV6_ADDRESS" ]; then
        ipv6_proxy
    fi
}

install_go() {
    local GO_WORKDIR GO_ENV GO_VER OS_ARCH

    GO_WORKDIR="/usr/local/go"
    GO_ENV="/etc/profile.d/go.sh"
    GO_VER="$(curl --retry 5 --insecure --location --silent "https://go.dev/dl/?mode=json" | awk '/version/ {print $2}' | sed -n '1s/.*"go\(.*\)".*/\1/p')"
    case "$(uname -m)" in
        i*86 | x86 ) OS_ARCH="386" ;;
        x86_64 | amd64 ) OS_ARCH="amd64" ;;
        armv6* ) OS_ARCH="armv6" ;;
        arm64 | aarch64 ) OS_ARCH="arm64" ;;
        * ) die "unsupported architecture: $(uname -m)" ;;
    esac
    _info_msg "$(_yellow "Start downloading the go install package.")"
    if ! curl --location --remote-name "${GITHUB_PROXY}go.dev/dl/go$GO_VER.linux-$OS_ARCH.tar.gz"; then
        die "Failed to download go install package, please check the network!"
    fi
    rm -rf "$GO_WORKDIR" >/dev/null 2>&1
    rm -f "$GO_ENV" >/dev/null 2>&1
    tar xzf "go$GO_VER.linux-$OS_ARCH.tar.gz" -C /usr/local
    tee "$GO_ENV" >/dev/null <<EOF
#!/bin/sh
# Copyright (c) 2025 honeok <honeok@disroot.org>

# GoLang Environment
export GOROOT=/usr/local/go
export GOPATH=\$GOROOT/gopath
export PATH=\$PATH:\$GOROOT/bin
EOF
    chmod +x "$GO_ENV"
    # shellcheck source=/dev/null
    . "$GO_ENV"
    mkdir -p "${GOPATH:?}"/{bin,pkg,src}
    chown -R "$USER":"$USER" "${GOPATH:?}"
}

install_check() {
    if _exists go >/dev/null 2>&1; then
        _suc_msg "$(_green "Go installed successfully!")"
        go version
    else
        die "Go installation failed, please check the error message."
    fi
}

go_proxy() {
    [ "$COUNTRY" = "CN" ] && go env -w GOPROXY=https://goproxy.cn,direct || return 0
}

# 全局参数 (1/2)
clrscr
check_root
check_cdn

# 主安装逻辑 (2/2)
install_go
clrscr
install_check
go_proxy