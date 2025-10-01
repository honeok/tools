#!/usr/bin/env bash
#
# Description: This script is used to retrieve the province and city information of a specified ip address in mainland china using public api services.
#
# Copyright (c) 2025 honeok <i@honeok.com>
# SPDX-License-Identifier: Apache-2.0
#
# References:
# https://lanye.org/web/940.html
# https://www.nodeseek.com/post-344659-1
# https://github.com/ihmily/ip-info-api

set -eEu

# 设置系统UTF-8语言环境
UTF8_LOCALE="$(locale -a 2>/dev/null | grep -iEm1 "UTF-8|utf8")"
[ -n "$UTF8_LOCALE" ] && export LC_ALL="$UTF8_LOCALE" LANG="$UTF8_LOCALE" LANGUAGE="$UTF8_LOCALE"

# 自定义彩色字体
_red() { printf "\033[91m%b\033[0m\n" "$*"; }
_err_msg() { printf "\033[41m\033[1mError\033[0m %b\n" "$*"; }

clear() {
    [ -t 1 ] && tput clear 2>/dev/null || printf "\033[2J\033[H" || command clear
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

# 验证是否是合法ip地址
check_legal_ipv4() {
    printf '%s' "$1" | tr -d '\n' | grep -Eq '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
}

check_legal_ipv6() {
    printf '%s' "$1" | tr -d '\n' | grep -Eq '^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$|^([0-9a-fA-F]{0,4}:){1,5}:[0-9a-fA-F]{0,4}$|^([0-9a-fA-F]{0,4}:){1,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}$|^([0-9a-fA-F]{0,4}:){1,3}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}$|^([0-9a-fA-F]{0,4}:){1,2}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}$|^[0-9a-fA-F]{0,4}::[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}$|^::[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}$'
}

# 验证是否是私有ipv4
check_private_ipv4() {
    printf '%s' "$1" | tr -d '\n' | grep -Eq '^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
}

baidu_api() {
    local CHECK_IP="$1"
    local IP_API IP PROVINCE CITY

    IP_API="$(curl -Ls "https://opendata.baidu.com/api.php?co=&resource_id=6006&oe=utf8&query=$CHECK_IP")"
    IP="$(sed -En 's/.*"origip":"([^"]+)".*/\1/p' <<< "$IP_API")"
    PROVINCE="$(sed -En 's/.*"location":"([^省市自治区特别行政区"]+)(省|市|自治区|特别行政区).*/\1/p' <<< "$IP_API")"
    CITY="$(sed -En 's/.*"location":"([^"]*?)(省|市|自治区|特别行政区)([^市"]+)市.*/\3/p' <<< "$IP_API")"

    ([[ -n "$IP" && -n "$PROVINCE" && -n "$CITY" ]] && echo "$IP $PROVINCE $CITY" && return 0) || return 1
}

pconline_api() {
    local CHECK_IP="$1"
    local IP_API IP PROVINCE CITY

    IP_API="$(curl -Ls "https://whois.pconline.com.cn/ipJson.jsp?ip=$CHECK_IP" | iconv -f gb2312 -t utf-8)"
    IP="$(sed -En 's/.*"ip":"([^"]+)".*/\1/p' <<< "$IP_API")"
    PROVINCE="$(sed -En 's/.*"pro":"([^"]+?)(省|市|自治区|特别行政区)".*/\1/p' <<< "$IP_API")"
    CITY="$(sed -En 's/.*"city":"([^"]+?)市".*/\1/p' <<< "$IP_API")"

    ([[ -n "$IP" && -n "$PROVINCE" && -n "$CITY" ]] && echo "$IP $PROVINCE $CITY" && return 0) || return 1
}

bilibili_api() {
    local CHECK_IP="$1"
    local IP_API IP PROVINCE CITY

    IP_API="$(curl -Ls "https://api.live.bilibili.com/ip_service/v1/ip_service/get_ip_addr?ip=$CHECK_IP")"
    IP="$(sed -En 's/.*"addr":"([^"]+)".*/\1/p' <<< "$IP_API")"
    PROVINCE="$(sed -En 's/.*"province":"([^"]+)".*/\1/p' <<< "$IP_API")"
    CITY="$(sed -En 's/.*"city":"([^"]+)".*/\1/p' <<< "$IP_API")"

    ([[ -n "$IP" && -n "$PROVINCE" && -n "$CITY" ]] && echo "$IP $PROVINCE $CITY" && return 0) || return 1
}

# runtime
iplocation() {
    local CHECK_IP="$1"

    baidu_api "$CHECK_IP" && return
    pconline_api "$CHECK_IP" && return
    bilibili_api "$CHECK_IP" && return
    die "Unknown IP information."
}

clear
check_root

if [ "$#" -gt 1 ]; then
    die "There are multiple parameters."
else
    CHECK_IP="${1:-$(awk '{print $1}' <<< "$SSH_CONNECTION")}"
    (check_legal_ipv4 "$CHECK_IP" && ! check_private_ipv4 "$CHECK_IP" && ! check_legal_ipv6 "$CHECK_IP") || die "must be a valid public ipv4 address."
    [[ "$(curl -Ls -4 "https://ipinfo.io/$CHECK_IP/country")" != "CN" ]] && die "The requesting ip does not belong to mainland china."
    ([ -n "$CHECK_IP" ] && iplocation "$CHECK_IP") || die "No valid ip provided."
fi
