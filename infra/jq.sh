#!/usr/bin/env bash
#
# Description: This script is used to quickly install the jq binary without extra dependencies.
#
# Copyright (c) 2025 honeok <i@honeok.com>
#
# SPDX-License-Identifier: Apache-2.0

set -eE

_red() { printf "\033[31m%b\033[0m\n" "$*"; }
_green() { printf "\033[32m%b\033[0m\n" "$*"; }
_yellow() { printf "\033[33m%b\033[0m\n" "$*"; }
_err_msg() { printf "\033[41m\033[1mError\033[0m %b\n" "$*"; }
_suc_msg() { printf "\033[42m\033[1mSuccess\033[0m %b\n" "$*"; }
_info_msg() { printf "\033[43m\033[1mInfo\033[0m %b\n" "$*"; }

# 设置PATH环境变量
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

# 各变量默认值
GITHUB_PROXY='https://gh-proxy.com/'

# 设置系统utf-8语言环境
UTF8_LOCALE="$(locale -a 2>/dev/null | grep -iEm1 "UTF-8|utf8")"
[ -n "$UTF8_LOCALE" ] && export LC_ALL="$UTF8_LOCALE" LANG="$UTF8_LOCALE" LANGUAGE="$UTF8_LOCALE"

clrscr() {
    [ -t 1 ] && tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
}

die() {
    _err_msg >&2 "$(_red "$@")"; exit 1
}

_exists() {
    local _CMD="$1"
    if type "$_CMD" >/dev/null 2>&1; then return;
    elif command -v "$_CMD" >/dev/null 2>&1; then return;
    elif which "$_CMD" >/dev/null 2>&1; then return;
    else return 1;
    fi
}

curl() {
    local RET TRY
    # 添加 --fail 不然404退出码也为0
    # 32位cygwin已停止更新, 证书可能有问题, 添加 --insecure
    # centos7 curl 不支持 --retry-connrefused --retry-all-errors 因此手动 retry
    for ((TRY=1; TRY<=5; TRY++)); do
        command curl --connect-timeout 10 --fail --insecure "$@"
        RET=$?
        if [ "$RET" -eq 0 ]; then
            return
        else
            # 403 404 错误或达到重试次数
            if [ "$RET" -eq 22 ] || [ "$TRY" -eq 5 ]; then
                return "$RET"
            fi
            sleep 1
        fi
    done
}

# 确保root用户运行
checkRoot() {
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
}

checkBash() {
    local BASH_VER
    BASH_VER="$(bash --version 2>/dev/null | head -n1 | awk '{print $4}' | cut -d. -f1)"
    if [ -z "$BASH_VERSION" ]; then
        die "This script needs to be run with bash, not sh!"
    fi
    if [[ "$BASH_VER" =~ ^[0-3]$ ]]; then
        die "Bash version is lower than 4.0!"
    fi
}

checkCdn() {
    if [[ -n "$GITHUB_PROXY" && "$(curl -Ls http://www.qualcomm.cn/cdn-cgi/trace | grep '^loc=' | cut -d= -f2 | grep .)" != "CN" ]]; then
        unset GITHUB_PROXY
    fi
}

checkJq() {
    if ! _exists jq; then
        die "jq already installed."
    fi
}

installJq() {
    local JQ_VER OS_NAME OS_ARCH
    OS_NAME="$(uname -s | sed 's/.*/\L&/' 2>/dev/null)"

    _info_msg "$(_yellow "Installing the jq command!")"
    JQ_VER="$(curl -Ls "${GITHUB_PROXY}https://api.github.com/repos/jqlang/jq/releases" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | sort -Vr | head -n1)"

    case "$(uname -m)" in
        i*86|x86) OS_ARCH="i386" ;;
        x86_64|x64|amd64) OS_ARCH="amd64" ;;
        armv6*) OS_ARCH="armel" ;;
        armv7*|arm) OS_ARCH="armhf" ;;
        armv8*|arm64|aarch64) OS_ARCH="arm64" ;;
        ppc64le) OS_ARCH="ppc64el" ;;
        s390x) OS_ARCH="s390x" ;;
        *) die "Unsupported architecture: $(uname -m)" ;;
    esac

    if !  curl -Lso /usr/bin/jq "${GITHUB_PROXY}https://github.com/jqlang/jq/releases/download/$JQ_VER/jq-$OS_NAME-$OS_ARCH"; then
        die "download failed, please check the network."
    fi
    if [ ! -x /usr/bin/jq ]; then
        chmod +x /usr/bin/jq >/dev/null 2>&1
    fi
    if _exists jq; then
        _suc_msg "$(_green "Download jq success!")"
        jq --version 2>&1 | sed 's/jq-\(.*\)/jq version: \1/'
    else
        die "Download jq failed."
    fi
}

clrscr
checkRoot
checkBash
checkCdn
checkJq
installJq