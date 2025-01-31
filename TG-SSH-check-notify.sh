#!/usr/bin/env bash
#
# Description: Implementing SSH login alerts through TELEGRAM.
#              This script is a modification based on Kejilion's TG-SSH-check-notify.sh script.
#
# Copyright (C) 2024 - 2025 honeok <honeok@duck.com>
#    __                         __  
#   / /  ___   ___  ___  ___   / /__
#  / _ \/ _ \ / _ \/ -_)/ _ \ /  '_/
# /_//_/\___//_//_/\__/ \___//_/\_\ 
#                                   
# License Information:
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License, version 3 or later.
#
# This program is distributed WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.

TELEGRAM_BOT_TOKEN="输入TG的机器人API"
CHAT_ID="输入TG的接收通知的账号ID"

ip_address() {
    local ipv4_services=("https://ipv4.ip.sb" "https://ipv4.icanhazip.com" "https://v4.ident.me")
    local ipv6_services=("https://ipv6.ip.sb" "https://ipv6.icanhazip.com" "https://v6.ident.me")

    ipv4_address=""
    ipv6_address=""

    for service in "${ipv4_services[@]}"; do
        ipv4_address=$(curl -fsL4 -m 3 "$service")
        if [[ "$ipv4_address" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            break
        fi
    done
    for service in "${ipv6_services[@]}"; do
        ipv6_address=$(curl -fsL6 -m 3 "$service")
        if [[ "$ipv6_address" =~ ^[0-9a-fA-F:]+$ ]]; then
            break
        fi
    done
}

geo_check() {
    local cloudflare_api ipinfo_api ipsb_api

    cloudflare_api=$(curl -sL -m 10 -A "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/81.0" "https://dash.cloudflare.com/cdn-cgi/trace" | sed -n 's/.*loc=\([^ ]*\).*/\1/p')
    ipinfo_api=$(curl -sL --connect-timeout 5 https://ipinfo.io/country)
    ipsb_api=$(curl -sL --connect-timeout 5 -A Mozilla https://api.ip.sb/geoip | sed -n 's/.*"country_code":"\([^"]*\)".*/\1/p')

    for api in "$cloudflare_api" "$ipinfo_api" "$ipsb_api"; do
        if [ -n "$api" ]; then
            country="$api"
            break
        fi
    done

    readonly country

    if [ -z "$country" ]; then
        echo "无法获取服务器所在地区，请检查网络后重试！"
        exit 1
    fi
}

ip_address
geo_check

# 获取登录信息
isp_info=$(curl -fsL --connect-timeout 5 https://ipinfo.io/org | sed -e 's/\"//g' | awk -F' ' '{print $2}')
ip_masked=$(echo "$ipv4_address" | awk -F'.' '{print "*."$3"."$4}')

login_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
login_time=$(date -u +'%Y年%m月%d日 %H:%M:%S' -d '+8 hours')

# 查询IP地址对应的地区信息
#location=$(curl -s https://ipapi.co/$IP/json/ | jq -r '.city')
location=$(curl -fsL "http://opendata.baidu.com/api.php?query=$ipv4_address&co=&resource_id=6006&oe=utf8&format=json" | grep '"location":' | sed 's/.*"location":"\([^"]*\)".*/\1/')
# 获取当前用户名
username=$(whoami)

# 发送Telegram消息
telegram_message="🚀 登录信息：
登录机器：${isp_info}-${country}-${ip_masked}
登录名：$username
登录IP：$login_ip
登录时间：$login_time
登录地区：$location"

curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" -d "chat_id=$CHAT_ID&text=$telegram_message" > /dev/null 2>&1