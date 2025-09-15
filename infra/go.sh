#!/usr/bin/env bash
#
# Description: This script is used to automatically installs or updates Go to the latest version.
#
# Copyright (c) 2025 honeok <i@honeok.com>
#
# SPDX-License-Identifier: Apache-2.0

set -eE

_red() { printf "\033[91m%b\033[0m\n" "$*"; }
_green() { printf "\033[92m%b\033[0m\n" "$*"; }
_yellow() { printf "\033[93m%b\033[0m\n" "$*"; }
_err_msg() { printf "\033[41m\033[1mError\033[0m %b\n" "$*"; }
_suc_msg() { printf "\033[42m\033[1mSuccess\033[0m %b\n" "$*"; }
_info_msg() { printf "\033[43m\033[1mInfo\033[0m %b\n" "$*"; }

# 设置PATH环境变量
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

# 各变量默认值
TEMP_DIR="$(mktemp -d)"

# 设置系统utf-8语言环境
UTF8_LOCALE="$(locale -a 2>/dev/null | grep -iEm1 "UTF-8|utf8")"
[ -n "$UTF8_LOCALE" ] && export LC_ALL="$UTF8_LOCALE" LANG="$UTF8_LOCALE" LANGUAGE="$UTF8_LOCALE"

trap 'rm -rf "${TEMP_DIR:?}" >/dev/null 2>&1' INT TERM EXIT

clrscr() {
    [ -t 1 ] && tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
}

die() {
    _err_msg >&2 "$(_red "$@")"; exit 1
}

# 临时工作目录
cd "$TEMP_DIR" >/dev/null 2>&1

_exists() {
    local _CMD="$1"
    if type "$_CMD" >/dev/null 2>&1; then return;
    elif command -v "$_CMD" >/dev/null 2>&1; then return;
    elif which "$_CMD" >/dev/null 2>&1; then return;
    else return 1;
    fi
}

curl() {
    local RET
    # 添加 --fail 不然404退出码也为0
    # 32位cygwin已停止更新, 证书可能有问题, 添加 --insecure
    # centos7 curl 不支持 --retry-connrefused --retry-all-errors 因此手动 retry
    for ((i=1; i<=5; i++)); do
        command curl --connect-timeout 10 --fail --insecure "$@"
        RET=$?
        if [ "$RET" -eq 0 ]; then
            return
        else
            # 403 404 错误或达到重试次数
            if [ "$RET" -eq 22 ] || [ "$i" -eq 5 ]; then
                return "$RET"
            fi
            sleep 1
        fi
    done
}

isChina() {
    if [ -z "$COUNTRY" ]; then
        if ! COUNTRY="$(curl -Ls http://www.qualcomm.cn/cdn-cgi/trace | grep '^loc=' | cut -d= -f2 | grep .)"; then
            die "Can not get location."
        fi
        echo 2>&1 "Location: $COUNTRY"
    fi
}

checkRoot() {
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
}

goInstall() {
    local GO_WORKDIR GO_ENV GO_MIRROR GO_VER OS_NAME OS_ARCH

    GO_WORKDIR="/usr/local/go"
    GO_ENV="/etc/profile.d/go.sh"
    OS_NAME="$(uname -s 2>/dev/null | sed 's/.*/\L&/')"

    if isChina; then
        GO_MIRROR="golang.google.cn"
    else
        GO_MIRROR="go.dev"
    fi

    GO_VER="$(curl -Ls "https://$GO_MIRROR/dl/?mode=json" | awk '/version/ {print $2}' | sed -n '1s/.*"go\(.*\)".*/\1/p')"

    case "$(uname -m)" in
        i*86|x86) OS_ARCH="386" ;;
        x86_64|amd64) OS_ARCH="amd64" ;;
        armv6*) OS_ARCH="armv6" ;;
        arm64|aarch64) OS_ARCH="arm64" ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac

    _info_msg "$(_yellow "Start downloading the go install package.")"
    if ! curl -LO "https://$GO_MIRROR/dl/go$GO_VER.$OS_NAME-$OS_ARCH.tar.gz"; then
        die "Failed to download go install package, please check the network!"
    fi
    rm -rf "$GO_WORKDIR" >/dev/null 2>&1
    rm -f "$GO_ENV" >/dev/null 2>&1
    tar fxz "go$GO_VER.linux-$OS_ARCH.tar.gz" -C /usr/local
    tee "$GO_ENV" >/dev/null <<EOF
#!/bin/sh
# Copyright (c) 2025 honeok <i@honeok.com>

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

goInfo() {
    if _exists go >/dev/null 2>&1; then
        _suc_msg "$(_green "Go installed successfully!")"
        go version 2>&1
    else
        die "Go installation failed, please check the error message."
    fi
}

goProxy() {
    if isChina; then
        go env -w GOPROXY=https://goproxy.cn,direct
    fi
}

clrscr
checkRoot
goInstall
goInfo
goProxy