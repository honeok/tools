#!/usr/bin/env bash
#
# Description: This script is used to accept the user's connection ip from the command line and obtain the weather in the user's location.
#
# Copyright (c) 2025 honeok <honeok@disroot.org>
#
# SPDX-License-Identifier: Apache-2.0

# 当前脚本版本号
readonly VERSION='v1.1.1 (2025.06.11)'

# https://www.graalvm.org/latest/reference-manual/ruby/UTF8Locale
if locale -a 2>/dev/null | grep -qiE -m 1 "UTF-8|utf8"; then
    export LANG=en_US.UTF-8
fi

# 自定义彩色字体
_red() { printf "\033[91m%b\033[0m\n" "$*"; }
_yellow() { printf "\033[93m%b\033[0m\n" "$*"; }
_cyan() { printf "\033[96m%b\033[0m\n" "$*"; }
_err_msg() { printf "\033[41m\033[1mError\033[0m %b\n" "$*"; }

# 各变量默认值
UA_BROWSER='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36'

# curl默认参数
declare -a CURL_OPTS=(--max-time 10 --retry 5 --retry-max-time 20)

# 清屏函数
clrscr() {
    ( [ -t 1 ] && tput clear 2>/dev/null ) || echo -e "\033[2J\033[H" || clear
}

# 打印错误信息并退出
die() {
    _err_msg "$(_red "$@")" >&2; exit 1
}

before_run() {
    if [ ! -t 1 ]; then
        die "This script requires a terminal environment."
    fi
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
    if [ -z "$BASH_VERSION" ] || [ "$(basename "$0")" = "sh" ]; then
        die "This script needs to be run with bash, not sh!"
    fi
    if [ -z "$SSH_CONNECTION" ] || [ -z "$(awk '{print $1}' <<< "$SSH_CONNECTION")" ]; then
        die "Failed to determine the client IP via SSH connection."
    fi
}

ip_info() {
    local USER_IP IP_API USER_REGION USER_CITY

    USER_IP="$(printf "%s" "$SSH_CONNECTION" | awk -F' ' '{print $1}')"
    IP_API="$(curl --user-agent "$UA_BROWSER" "${CURL_OPTS[@]}" -fsL "https://api.ipbase.com/v1/json/$USER_IP")" || \
    IP_API="$(curl --user-agent "$UA_BROWSER" "${CURL_OPTS[@]}" -fsL "https://api.ip.sb/geoip/$USER_IP")" || \
    die "unable to obtain valid ip info, please check the network."
    USER_REGION="$(sed -En 's/.*"(region_name|region)":[ ]*"([^"]+)".*/\2/p' <<< "$IP_API")"
    USER_CITY="$(sed -En 's/.*"city"\s*:\s*"([^"]+)".*/\1/p' <<< "$IP_API")"
    echo "$USER_REGION" "$USER_CITY"
}

weather_run() {
    local USER_REGION USER_CITY
    read -r USER_REGION USER_CITY <<< "$(ip_info)"

    echo "$(_yellow "Script Version : $VERSION") $(_cyan "\xf0\x9f\x8c\xa1\xef\xb8\x8f")"
    echo
    echo "$(_yellow "Welcome! Users from") $(_cyan "${USER_REGION:-Unknown Region}")!"
    echo
    curl "${CURL_OPTS[@]}" -fsL "http://wttr.in/$USER_CITY?1"
}

weather() {
    clrscr
    before_run
    weather_run
}

weather