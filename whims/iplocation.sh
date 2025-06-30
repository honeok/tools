#!/usr/bin/env bash
#
# Description: This script is used to retrieve the province and city information of a specified ip address in mainland china using public api services.
#
# Copyright (c) 2025 honeok <honeok@disroot.org>
#
# References:
# https://lanye.org/web/940.html
# https://www.nodeseek.com/post-344659-1
# https://github.com/ihmily/ip-info-api
#
# SPDX-License-Identifier: Apache-2.0

# Color fonts
_red() { printf "\033[91m%b\033[0m\n" "$*"; }
_err_msg() { printf "\033[41m\033[1mError\033[0m %b\n" "$*"; }

# User Agent
UA_BROWSER='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36'

UTF8_LOCALE="$(locale -a 2>/dev/null | grep -iEm1 "UTF-8|utf8")"
[ -n "$UTF8_LOCALE" ] && export LC_ALL="$UTF8_LOCALE" LANG="$UTF8_LOCALE" LANGUAGE="$UTF8_LOCALE"

# Clear screen
clrscr() {
    ([ -t 1 ] && tput clear 2>/dev/null) || echo -e "\033[2J\033[H" || clear
}

# Print an error message and exit
die() {
    _err_msg "$(_red "$@")" >&2; exit 1
}

check_root() {
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
}

# Verify whether it is a valid ipv4 address
check_legal_ipv4() {
    printf '%s' "$1" | tr -d '\n' | grep -Eq '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
}

check_legal_ipv6() {
    printf '%s' "$1" | tr -d '\n' | grep -Eq '^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$|^([0-9a-fA-F]{0,4}:){1,5}:[0-9a-fA-F]{0,4}$|^([0-9a-fA-F]{0,4}:){1,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}$|^([0-9a-fA-F]{0,4}:){1,3}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}$|^([0-9a-fA-F]{0,4}:){1,2}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}$|^[0-9a-fA-F]{0,4}::[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}$|^::[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}$'
}

# verify whether it is a private ipv4 address
check_private_ipv4() {
    printf '%s' "$1" | tr -d '\n' | grep -Eq '^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
}

iqiyi_api() {
    local CHECK_IP="$1"
    local IP_API IP PROVINCE CITY

    IP_API="$(curl --user-agent "$UA_BROWSER" --max-time 5 --insecure --location --silent "https://mesh.if.iqiyi.com/aid/ip/info?version=1.1.1&ip=$CHECK_IP")"
    IP="$CHECK_IP"
    PROVINCE="$(sed -En 's/.*"provinceCN":"([^"]+)".*/\1/p' <<< "$IP_API")"
    CITY="$(sed -En 's/.*"cityCN":"([^"]+)".*/\1/p' <<< "$IP_API")"

    ([[ -n "$IP" && -n "$PROVINCE" && -n "$CITY" ]] && echo "$IP $PROVINCE $CITY" && return 0) || return 1
}

baidu_api() {
    local CHECK_IP="$1"
    local IP_API IP PROVINCE CITY

    IP_API="$(curl --user-agent "$UA_BROWSER" --max-time 5 --insecure --location --silent "https://opendata.baidu.com/api.php?co=&resource_id=6006&oe=utf8&query=$CHECK_IP")"
    IP="$(sed -En 's/.*"origip":"([^"]+)".*/\1/p' <<< "$IP_API")"
    PROVINCE="$(sed -En 's/.*"location":"([^省市自治区特别行政区"]+)(省|市|自治区|特别行政区).*/\1/p' <<< "$IP_API")"
    CITY="$(sed -En 's/.*"location":"([^"]*?)(省|市|自治区|特别行政区)([^市"]+)市.*/\3/p' <<< "$IP_API")"

    ([[ -n "$IP" && -n "$PROVINCE" && -n "$CITY" ]] && echo "$IP $PROVINCE $CITY" && return 0) || return 1
}

baidubce_api() {
    local CHECK_IP="$1"
    local IP_API IP PROVINCE CITY

    IP_API="$(curl --user-agent "$UA_BROWSER" --max-time 5 --insecure --location --silent "https://qifu-api.baidubce.com/ip/geo/v1/district?ip=$CHECK_IP")"
    IP="$(sed -En 's/.*"ip":"([^"]+)".*/\1/p' <<< "$IP_API")"
    PROVINCE="$(sed -En 's/.*"prov":"([^"]+?)(省|市|自治区|特别行政区)".*/\1/p' <<< "$IP_API")"
    CITY="$(sed -En 's/.*"city":"([^"]+?)市".*/\1/p' <<< "$IP_API")"

    ([[ -n "$IP" && -n "$PROVINCE" && -n "$CITY" ]] && echo "$IP $PROVINCE $CITY" && return 0) || return 1
}

pconline_api() {
    local CHECK_IP="$1"
    local IP_API IP PROVINCE CITY

    IP_API="$(curl --user-agent "$UA_BROWSER" --max-time 5 --insecure --location --silent "https://whois.pconline.com.cn/ipJson.jsp?ip=$CHECK_IP" | iconv -f gb2312 -t utf-8)"
    IP="$(sed -En 's/.*"ip":"([^"]+)".*/\1/p' <<< "$IP_API")"
    PROVINCE="$(sed -En 's/.*"pro":"([^"]+?)(省|市|自治区|特别行政区)".*/\1/p' <<< "$IP_API")"
    CITY="$(sed -En 's/.*"city":"([^"]+?)市".*/\1/p' <<< "$IP_API")"

    ([[ -n "$IP" && -n "$PROVINCE" && -n "$CITY" ]] && echo "$IP $PROVINCE $CITY" && return 0) || return 1
}

bilibili_api() {
    local CHECK_IP="$1"
    local IP_API IP PROVINCE CITY

    IP_API="$(curl --user-agent "$UA_BROWSER" --max-time 5 --insecure --location --silent "https://api.live.bilibili.com/ip_service/v1/ip_service/get_ip_addr?ip=$CHECK_IP")"
    IP="$(sed -En 's/.*"addr":"([^"]+)".*/\1/p' <<< "$IP_API")"
    PROVINCE="$(sed -En 's/.*"province":"([^"]+)".*/\1/p' <<< "$IP_API")"
    CITY="$(sed -En 's/.*"city":"([^"]+)".*/\1/p' <<< "$IP_API")"

    ([[ -n "$IP" && -n "$PROVINCE" && -n "$CITY" ]] && echo "$IP $PROVINCE $CITY" && return 0) || return 1
}

# runtime
iplocation() {
    local CHECK_IP="$1"

    iqiyi_api "$CHECK_IP" && return 0
    baidu_api "$CHECK_IP" && return 0
    baidubce_api "$CHECK_IP" && return 0
    pconline_api "$CHECK_IP" && return 0
    bilibili_api "$CHECK_IP" && return 0
    die "Unknown IP information."
}

# global Parameters (1/2)
clrscr
check_root

# main operation logic (2/2)
if [ "$#" -gt 1 ]; then
    die "There are multiple parameters."
else
    CHECK_IP="${1:-$(awk '{print $1}' <<< "$SSH_CONNECTION")}"
    (check_legal_ipv4 "$CHECK_IP" && ! check_private_ipv4 "$CHECK_IP" && ! check_legal_ipv6 "$CHECK_IP") || die "must be a valid public ipv4 address."
    [[ "$(curl --retry 2 --location --silent --ipv4 "https://ipinfo.io/$CHECK_IP/country")" != CN ]] && die "The requesting ip does not belong to mainland china."
    ([ -n "$CHECK_IP" ] && iplocation "$CHECK_IP") || die "No valid ip provided."
fi