#!/usr/bin/env bash
#
# Description: This script is used to quickly install the shellcheck binary without extra dependencies.
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

# 设置系统utf-8语言环境
UTF8_LOCALE="$(locale -a 2>/dev/null | grep -iEm1 "UTF-8|utf8")"
[ -n "$UTF8_LOCALE" ] && export LC_ALL="$UTF8_LOCALE" LANG="$UTF8_LOCALE" LANGUAGE="$UTF8_LOCALE"

# 各变量默认值
TEMP_DIR="$(mktemp -d)"
GITHUB_PROXY='https://gh-proxy.com/'

trap 'rm -rf "${TEMP_DIR:?}" >/dev/null 2>&1' SIGINT SIGTERM EXIT

clrscr() {
    [ -t 1 ] && tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
}

die() {
    _err_msg >&2 "$(_red "$@")"; exit 1
}

cd "$TEMP_DIR" >/dev/null 2>&1 || die "Unable to enter the work path."

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

# 确保root用户运行
check_root() {
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
}

check_bash() {
    local BASH_VER

    # https://github.com/xykt/IPQuality/issues/28
    BASH_VER="$(bash --version | head -n1 | awk -F ' ' '{for (i=1; i<=NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+/) {print $i; exit}}' | cut -d . -f1)"
    if [ -z "$BASH_VERSION" ]; then
        die "This script needs to be run with bash, not sh!"
    fi
    if [ -z "$BASH_VER" ] || ! [[ "$BASH_VER" =~ ^[0-9]+$ ]]; then
        die "Failed to parse Bash version!"
    fi
    if [ "$BASH_VER" -lt 4 ]; then
        die "Bash version is lower than 4.0!"
    fi
}

check_cdn() {
    if [[ -n "$GITHUB_PROXY" && "$(curl -Ls http://www.qualcomm.cn/cdn-cgi/trace | grep '^loc=' | cut -d= -f2 | grep .)" != "CN" ]]; then
        unset GITHUB_PROXY
    fi
}

check_sc() {
    if _exists shellcheck; then
        die "shellcheck already installed."
    fi
}

install_sc() {
    local SC_VER OS_NAME OS_ARCH
    OS_NAME="$(uname -s 2>/dev/null | sed 's/.*/\L&/')"

    _info_msg "$(_yellow "Installing the shellcheck command!")"
    SC_VER="$(curl -Ls "${GITHUB_PROXY}https://api.github.com/repos/koalaman/shellcheck/releases" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | sort -Vr | head -n1)"

    case "$(uname -m)" in
        x86_64|amd64) OS_ARCH="x86_64" ;;
        armv6*) OS_ARCH="armv6hf" ;;
        armv8*|arm64|aarch64) OS_ARCH="aarch64" ;;
        riscv64) OS_ARCH="riscv64" ;;
        *) die "Unsupported architecture: $(uname -m)" ;;
    esac

    if ! curl -LO "${GITHUB_PROXY}https://github.com/koalaman/shellcheck/releases/download/$SC_VER/shellcheck-$SC_VER.$OS_NAME.$OS_ARCH.tar.xz"; then
        die "download failed, please check the network."
    fi

    tar fJx "shellcheck-$SC_VER.$OS_NAME.$OS_ARCH.tar.xz"

    if [ ! -x "shellcheck-$SC_VER/shellcheck" ]; then
        chmod +x "shellcheck-$SC_VER/shellcheck" >/dev/null 2>&1
    fi
    mv "shellcheck-$SC_VER/shellcheck" /usr/bin/shellcheck >/dev/null 2>&1
    if _exists shellcheck; then
        _suc_msg "$(_green "Download shellcheck success!")"
        shellcheck -V 2>&1 | sed -n 's/^version: \(.*\)$/Shellcheck Version: \1/p'
    else
        die "Download shellcheck failed."
    fi
}

clrscr
check_root
check_bash
check_cdn
check_sc
install_sc