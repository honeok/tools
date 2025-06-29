#!/usr/bin/env bash
#
# Description: This script is used to install the binary file jq command.
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
GITHUB_PROXY='https://ghproxy.badking.pp.ua/'

# 设置系统utf-8语言环境
UTF8_LOCALE="$(locale -a 2>/dev/null | grep -iEm1 "UTF-8|utf8")"
[ -n "$UTF8_LOCALE" ] && export LC_ALL="$UTF8_LOCALE" LANG="$UTF8_LOCALE" LANGUAGE="$UTF8_LOCALE"

clrscr() {
    ([ -t 1 ] && tput clear 2>/dev/null) || echo -e "\033[2J\033[H" || clear
}

die() {
    _err_msg >&2 "$(_red "$@")"; exit 1
}

_exists() {
    local _CMD="$1"
    if type "$_CMD" >/dev/null 2>&1; then return 0;
    elif command -v "$_CMD" >/dev/null 2>&1; then return 0;
    elif which "$_CMD" >/dev/null 2>&1; then return 0;
    else return 1;
    fi
}

# 确保root用户运行
check_root() {
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
}

check_bash() {
    local BASH_VER
    BASH_VER="$(bash --version 2>/dev/null | head -n1 | awk '{print $4}' | cut -d. -f1)"
    if [ -z "$BASH_VERSION" ] || [ "$(basename "$0")" = "sh" ]; then
        die "This script needs to be run with bash, not sh!"
    fi
    if [[ "$BASH_VER" =~ ^[0-3]$ ]]; then
        die "Bash version is lower than 4.0!"
    fi
}

check_cdn() {
    local COUNTRY IPV4_ADDRESS IPV6_ADDRESS

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
    COUNTRY="$(curl -m5 -Ls https://www.qualcomm.cn/cdn-cgi/trace | grep -i '^loc=' | cut -d'=' -f2 | grep .)"
    IPV4_ADDRESS="$(curl -m5 -Ls -4 https://www.qualcomm.cn/cdn-cgi/trace | grep -i '^ip=' | cut -d'=' -f2 | grep .)"
    IPV6_ADDRESS="$(curl -m5 -Ls -6 https://www.qualcomm.cn/cdn-cgi/trace | grep -i '^ip=' | cut -d'=' -f2 | grep .)"
    if [ "$COUNTRY" != "CN" ] && [ -n "$IPV4_ADDRESS" ]; then
        unset GITHUB_PROXY
    elif [ "$COUNTRY" != "CN" ] && [ -z "$IPV4_ADDRESS" ] && [ -n "$IPV6_ADDRESS" ]; then
        ipv6_proxy
    fi
}

check_jq() {
    ! _exists jq || die "jq already installed."
}

install_jq() {
    local JQ_VER OS_ARCH

    _info_msg "$(_yellow "Installing the jq command!")"
    JQ_VER="$(curl --retry 2 -m5 -Ls https://api.github.com/repos/jqlang/jq/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')"
    JQ_VER="${JQ_VER:-jq-1.8.0}"

    case "$(uname -m)" in
        i*86 | x86 ) OS_ARCH="i386" ;;
        x86_64 | x64 | amd64 ) OS_ARCH="amd64" ;;
        armv6* ) OS_ARCH="armel" ;;
        armv7* | arm ) OS_ARCH="armhf" ;;
        armv8* | arm64 | aarch64 ) OS_ARCH="arm64" ;;
        ppc64le ) OS_ARCH="ppc64el" ;;
        s390x ) OS_ARCH="s390x" ;;
        * ) die "Unsupported architecture: $(uname -m)" ;;
    esac

    curl --retry 2 -Ls -o /usr/bin/jq "${GITHUB_PROXY}https://github.com/jqlang/jq/releases/download/${JQ_VER}/jq-linux-${OS_ARCH}"
    [ ! -x /usr/bin/jq ] && chmod +x /usr/bin/jq
    (_exists jq && _suc_msg "$(_green "Download jq success!")" && jq --version 2>&1 | sed 's/jq-\(.*\)/jq version: \1/') || die "Download jq failed."
}

clrscr
check_root
check_bash
check_jq
check_cdn
install_jq