#!/usr/bin/env bash
#
# Description: This script is used to accept the user's connection ip from the command line and obtain the weather in the user's location.
#
# Copyright (c) 2025 honeok <i@honeok.com>
#
# SPDX-License-Identifier: Apache-2.0

set -eE

# 当前脚本版本号
readonly VERSION='v25.9.27'

# 设置PATH环境变量
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

# 设置系统UTF-8语言环境
UTF8_LOCALE="$(locale -a 2>/dev/null | grep -iEm1 "UTF-8|utf8")"
[ -n "$UTF8_LOCALE" ] && export LC_ALL="$UTF8_LOCALE" LANG="$UTF8_LOCALE" LANGUAGE="$UTF8_LOCALE"

# 自定义彩色字体
_red() { printf "\033[91m%b\033[0m\n" "$*"; }
_yellow() { printf "\033[93m%b\033[0m\n" "$*"; }
_cyan() { printf "\033[96m%b\033[0m\n" "$*"; }
_err_msg() { printf "\033[41m\033[1mError\033[0m %b\n" "$*"; }

clear() {
    [ -t 1 ] && tput clear 2>/dev/null || echo -e "\033[2J\033[H" || command clear
}

die() {
    _err_msg >&2 "$(_red "$@")"; exit 1
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

check_root() {
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
}

check_bash() {
    local BASH_VER

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

check_session() {
    if [ -z "$SSH_CONNECTION" ] || [ -z "$(awk '{print $1}' <<< "$SSH_CONNECTION")" ]; then
        die "Failed to determine the client IP via SSH connection."
    fi
}

ip_info() {
    local USER_IP IP_API USER_REGION USER_CITY

    USER_IP="$(awk '{print $1}' <<< "$SSH_CONNECTION")"
    IP_API="$(curl -Ls "https://api.ipbase.com/v1/json/$USER_IP")" || \
        IP_API="$(curl -Ls "https://api.ip2location.io?ip=$USER_IP&format=json")" || \
        IP_API="$(curl --user-agent Mozilla -Ls "https://api.ip.sb/geoip/$USER_IP")" || \
        IP_API="$(curl -Ls "https://freeipapi.com/api/json/$USER_IP")" || \
    die "unable to obtain valid ip info, please check the network."
    USER_REGION="$(sed -En 's/.*"(region_name|regionName|region)":[ ]*"([^"]+)".*/\2/p' <<< "$IP_API")"
    USER_CITY="$(sed -En 's/.*"(city_name|cityName|city)":[ ]*"([^"]+)".*/\2/p' <<< "$IP_API")"
    echo "$USER_REGION" "$USER_CITY"
}

weather() {
    local USER_REGION USER_CITY

    read -r USER_REGION USER_CITY <<< "$(ip_info)"
    echo "$(_yellow "Script Version : $VERSION") $(_cyan "\xf0\x9f\x8c\xa1\xef\xb8\x8f")"
    echo
    echo "$(_yellow "Welcome! Users from") $(_cyan "${USER_REGION:-Unknown Region}")!"
    echo
    curl -Ls "https://wttr.in/$USER_CITY?1"
}

main() {
    clear
    check_root
    check_bash
    check_session
    weather
}

main
