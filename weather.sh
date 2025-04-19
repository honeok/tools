#!/usr/bin/env bash
#
# Description: gets the current weather for the logged in user.
#
# Copyright (c) 2025 honeok <honeok@duck.com>
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

red='\033[91m'
yellow='\033[93m'
cyan='\033[96m'
white='\033[0m'
_red() { printf "$red%s$white\n" "$*"; }
_yellow() { printf "$yellow%s$white\n" "$*"; }
_cyan() { printf "$cyan%s$white\n" "$*"; }
_err_msg() { printf "\033[41m\033[1mError$white %s\n" "$*"; }

# 各变量默认值
UA_BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

# 清屏函数
clear_screen() {
    [ -t 1 ] && tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
}

pre_check() {
    if [ ! -t 1 ]; then
        _err_msg "$(_red 'This script requires a terminal environment.')" 2>&1 && exit 1
    fi
    if [ "$(id -ru)" -ne 0 ] || [ "$EUID" -ne 0 ]; then
        _err_msg "$(_red 'This script must be run as root!')" >&2 && exit 1
    fi
    if [ "$(ps -p $$ -o comm=)" != 'bash' ] || readlink /proc/$$/exe | grep -q 'dash'; then
        _err_msg "$(_red 'This script requires Bash as the shell interpreter!')" >&2 && exit 1
    fi
    if [ -z "$SSH_CONNECTION" ]; then
        _err_msg "$(_red 'Failed to determine the client IP via SSH connection.')" >&2 && exit 1
    fi
}

weather_check() {
    local USER_IP IP_API USER_REGION USER_CITY

    USER_IP=$(echo "$SSH_CONNECTION" | cut -d ' ' -f 1)
    IP_API=$(curl -A "$UA_BROWSER" -fsSL -m 5 --retry 1 --compressed "http://api.ipbase.com/v1/json/$USER_IP")
    USER_REGION=$(echo "$IP_API" | awk -F'"region_name":"' '{print $2}' | sed 's/".*//')
    USER_CITY=$(echo "$IP_API" | awk -F'"city":"' '{print $2}' | sed 's/".*//')

    echo "$(_yellow 'Welcome! Users from') $(_cyan "${USER_REGION:-Unknown Region}")!"
    printf "\n"
    curl -fsSL -m 5 --retry 1 --compressed "http://wttr.in/$USER_CITY?1"
}

weather() {
    clear_screen
    pre_check
    weather_check
}

weather