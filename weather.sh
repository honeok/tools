#!/usr/bin/env bash
#
# Description: Gets the current weather for the logged-in user.
#
# Copyright (C) 2025 honeok <honeok@duck.com>
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

red='\033[91m'
yellow='\033[93m'
cyan='\033[96m'
white='\033[0m'
_red() { echo -e "${red}$*${white}"; }
_yellow() { echo -e "${yellow}$*${white}"; }
_cyan() { echo -e "${cyan}$*${white}"; }

_err_msg() { echo -e "\033[41m\033[1mwarn${white} $*"; }

# 清屏函数
clear_screen() {
    if [ -t 1 ]; then
        tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
    fi
}

pre_check() {
    if [ ! -t 1 ]; then
        _err_msg "$(_red 'Error: This script requires a terminal environment.')" 2>&1 && exit 1
    fi
    if [ "$(id -ru)" -ne "0" ] || [ "$EUID" -ne "0" ]; then
        _err_msg "$(_red 'Error: This script must be run as root!')" && exit 1
    fi
    if [ "$(ps -p $$ -o comm=)" != "bash" ] || readlink /proc/$$/exe | grep -q "dash"; then
        _err_msg "$(_red 'Error: This script requires Bash as the shell interpreter!')" && exit 1
    fi
    if [ -z "$SSH_CONNECTION" ]; then
        _err_msg "$(_red 'Error: Failed to determine the client IP via SSH connection.')" && exit 1
    fi
}

weather_check() {
    local userIP ip_Api user_Region user_City

    userIP=$(echo "$SSH_CONNECTION" | cut -d ' ' -f 1)
    ip_Api=$(curl -fsk -m 5 "http://ip-api.com/json/$userIP")
    user_Region=$(echo "$ip_Api" | awk -F'"regionName":"' '{print $2}' | sed 's/".*//')
    user_City=$(echo "$ip_Api" | awk -F'"city":"' '{print $2}' | sed 's/".*//')

    echo "$(_yellow 'Welcome! Users from') $(_cyan "${user_Region:-Unknown Region}")!"
    printf "\n"
    curl -fsk -m 5 "wttr.in/$user_City?1"
}

weather() {
    clear_screen
    pre_check
    weather_check
}

weather