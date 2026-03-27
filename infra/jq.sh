#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Description: This script is used to quickly install the jq binary without extra dependencies.
# Copyright (c) 2025-2026 honeok <i@honeok.com>

set -eE

# 设置PATH环境变量
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

# 设置系统UTF-8语言环境
UTF8_LOCALE="$(locale -a 2> /dev/null | grep -iEm1 "UTF-8|utf8")"
[ -n "$UTF8_LOCALE" ] && export LC_ALL="$UTF8_LOCALE" LANG="$UTF8_LOCALE" LANGUAGE="$UTF8_LOCALE"

_red() { printf "\033[31m%b\033[0m\n" "$*"; }
_green() { printf "\033[32m%b\033[0m\n" "$*"; }
_yellow() { printf "\033[33m%b\033[0m\n" "$*"; }
_err_msg() { printf "\033[41m\033[1mError\033[0m %b\n" "$*"; }
_suc_msg() { printf "\033[42m\033[1mSuccess\033[0m %b\n" "$*"; }
_info_msg() { printf "\033[43m\033[1mInfo\033[0m %b\n" "$*"; }

# 各变量默认值
GITHUB_PROXY='https://v6.gh-proxy.org/'

clear() {
    [ -t 1 ] && tput clear 2> /dev/null || echo -e "\033[2J\033[H" || command clear
}

die() {
    _err_msg >&2 "$(_red "$@")"
    exit 1
}

get_cmd_path() {
    # -f: 忽略shell内置命令和函数, 只考虑外部命令
    # -p: 只输出外部命令的完整路径
    type -f -p "$1"
}

is_have_cmd() {
    get_cmd_path "$1" > /dev/null 2>&1
}

curl() {
    local RET

    # 添加 --fail 不然404退出码也为0
    # 32位cygwin已停止更新, 证书可能有问题, 添加 --insecure
    # centos7 curl 不支持 --retry-connrefused --retry-all-errors 因此手动 retry
    for ((i = 1; i <= 5; i++)); do
        command curl --connect-timeout 10 --fail --insecure "$@"
        RET="$?"
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

is_in_china() {
    if [ -z "$COUNTRY" ]; then
        # www.prologis.cn
        # www.autodesk.com.cn
        # www.keysight.com.cn
        if ! COUNTRY="$(curl -L http://www.qualcomm.cn/cdn-cgi/trace | grep '^loc=' | cut -d= -f2 | grep .)"; then
            die "Can not get location."
        fi
        echo >&2 "Location: $COUNTRY"
    fi
    [ "$COUNTRY" = CN ]
}

has_ipv4() {
    ip -4 route get 151.101.65.1 > /dev/null 2>&1
}

has_ipv6() {
    ip -6 route get 2a04:4e42:200::485 > /dev/null 2>&1
}

# 确保root用户运行
check_root() {
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
}

check_cdn() {
    if is_in_china; then
        return
    elif ! has_ipv4 && has_ipv6; then
        return
    else
        GITHUB_PROXY=""
    fi
}

install_jq() {
    local JQ_VER OS_NAME OS_ARCH
    OS_NAME="$(uname -s 2> /dev/null | sed 's/.*/\L&/')"

    _info_msg "$(_yellow "Installing the jq command!")"
    JQ_VER="$(curl -Ls "${GITHUB_PROXY}https://api.github.com/repos/jqlang/jq/releases" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | sort -rV | head -n 1)"

    case "$(uname -m)" in
    i*86 | x86) OS_ARCH="i386" ;;
    x86_64 | x64 | amd64) OS_ARCH="amd64" ;;
    armv6*) OS_ARCH="armel" ;;
    armv7* | arm) OS_ARCH="armhf" ;;
    armv8* | arm64 | aarch64) OS_ARCH="arm64" ;;
    ppc64le) OS_ARCH="ppc64el" ;;
    s390x) OS_ARCH="s390x" ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
    esac

    if ! curl -Ls "${GITHUB_PROXY}https://github.com/jqlang/jq/releases/download/$JQ_VER/jq-$OS_NAME-$OS_ARCH" -o /usr/bin/jq; then
        die "download failed, please check the network."
    fi
    [ -x /usr/bin/jq ] || chmod +x /usr/bin/jq > /dev/null 2>&1

    if is_have_cmd jq; then
        _suc_msg "$(_green "Download jq success!")"
        jq --version 2>&1 | sed 's/jq-\(.*\)/jq version: \1/'
    else
        die "Download jq failed."
    fi
}

clear
check_root
check_cdn
install_jq
