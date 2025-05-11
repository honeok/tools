#!/usr/bin/env bash
#
# Description: gets the current weather for the logged in user.
#
# Copyright (c) 2025 honeok <honeok@duck.com>
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

_red() { printf "\033[91m%s\033[0m\n" "$*"; }
_yellow() { printf "\033[93m%s\033[0m\n" "$*"; }
_cyan() { printf "\033[96m%s\033[0m\n" "$*"; }
_err_msg() { printf "\033[41m\033[1mError\033[0m %s\n" "$*"; }

# 各变量默认值
UA_BROWSER='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'

# curl默认参数
declare -a CURL_OPTS=(--max-time 5 --retry 1 --retry-max-time 10)

# 清屏函数
clear_screen() {
    [ -t 1 ] && tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
}

pre_check() {
    [ ! -t 1 ] && { _err_msg "$(_red 'This script requires a terminal environment.')" 2>&1; exit 1; }
    [ "$EUID" -ne 0 ] && { _err_msg "$(_red 'This script must be run as root!')" >&2; exit 1; }
    [ -z "$SSH_CONNECTION" ] && { _err_msg "$(_red 'Failed to determine the client IP via SSH connection.')" >&2; exit 1; }
    [ -z "$BASH_VERSION" ] || [ "$(basename "$0")" = "sh" ] && { _err_msg "$(_red 'This script needs to be run with bash, not sh!')" >&2; exit 1; }
}

weather_check() {
    local USER_IP IP_API USER_REGION USER_CITY
    USER_IP=$(printf "%s" "$SSH_CONNECTION" | awk -F' ' '{print $1}')
    IP_API=$(curl --user-agent "$UA_BROWSER" "${CURL_OPTS[@]}" -fsL "http://api.ipbase.com/v1/json/$USER_IP")
    USER_REGION=$(printf "%s" "$IP_API" | awk -F'"region_name":"' '{print $2}' | sed 's/".*//')
    USER_CITY=$(printf "%s" "$IP_API" | awk -F'"city":"' '{print $2}' | sed 's/".*//')

    echo "$(_yellow 'Welcome! Users from') $(_cyan "${USER_REGION:-Unknown Region}")!"
    echo
    curl "${CURL_OPTS[@]}" -fsL "http://wttr.in/$USER_CITY?1"
}

weather() {
    clear_screen
    pre_check
    weather_check
}

weather