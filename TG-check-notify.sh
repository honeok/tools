#!/usr/bin/env bash
#
# Description: Real-time monitoring and alerting of CPU, memory, disk usage, traffic, and SSH logins via Telegram Bot.
#
# Forked and Modified By: Copyright (C) 2024 - 2025 honeok <honeok@duck.com>
#
# Original Project: https://github.com/kejilion/sh
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

# 你需要配置Telegram Bot Token和Chat ID
TELEGRAM_BOT_TOKEN="输入TG的机器人API"
CHAT_ID="输入TG的接收通知的账号ID"

# 可以修改监控阈值设置
cpu_threshold=70
mem_threshold=70
disk_threshold=70
network_threshold_gb=1000

ip_address() {
    local ipv4_services=("https://ipv4.ip.sb" "https://ipv4.icanhazip.com" "https://v4.ident.me")

    ipv4_address=""

    for service in "${ipv4_services[@]}"; do
        ipv4_address=$(curl -fsL4 -m 3 "$service")
        if [[ "$ipv4_address" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            break
        fi
    done
}

geo_check() {
    local cloudflare_api ipinfo_api ipsb_api

    cloudflare_api=$(curl -fsL -m 10 -A "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/81.0" "https://dash.cloudflare.com/cdn-cgi/trace" | sed -n 's/.*loc=\([^ ]*\).*/\1/p')
    ipinfo_api=$(curl -fsL --connect-timeout 5 https://ipinfo.io/country)
    ipsb_api=$(curl -fsL --connect-timeout 5 -A Mozilla https://api.ip.sb/geoip | sed -n 's/.*"country_code":"\([^"]*\)".*/\1/p')

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

# 获取设备信息
isp_info=$(curl -fsL --connect-timeout 5 https://ipinfo.io/org | sed -e 's/\"//g' | awk -F' ' '{print $2}')

ip_masked=$(echo "$ipv4_address" | awk -F'.' '{print "*."$3"."$4}')

# 发送Telegram通知的函数
send_telegram_message() {
    local message="$1"
    curl -fsL -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" -d "chat_id=$CHAT_ID" -d "text=$message"
}

# 获取CPU使用率
get_cpu_usage() {
    awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.0f\n", (($2+$4-u1) * 100 / (t-t1))}' \
        <(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat)
}

# 获取内存使用率
get_mem_usage() {
    free | awk '/Mem/ {printf("%.0f"), $3/$2 * 100}'
}

# 获取硬盘使用率
get_disk_usage() {
    df / | awk 'NR==2 {print $5}' | sed 's/%//'
}

# 获取总的接收流量（字节数）
get_rx_bytes() {
    awk 'BEGIN { rx_total = 0 }
        NR > 2 { rx_total += $2 }
        END {
            printf("%.2f", rx_total / (1024 * 1024 * 1024));
        }' /proc/net/dev
}

# 获取总的发送流量（字节数）
get_tx_bytes() {
    awk 'BEGIN { tx_total = 0 }
        NR > 2 { tx_total += $10 }
        END {
            printf("%.2f", tx_total / (1024 * 1024 * 1024));
        }' /proc/net/dev
}

# 检查并发送通知
check_and_message() {
    local usage="$1"
    local type="$2"
    local threshold="$3"
    # local current_value="$4"

    if (( $(echo "$usage > $threshold" | bc -l) )); then
        send_telegram_message "警告: ${isp_info}-${country}-${ip_masked} 的 $type 使用率已达到 $usage%，超过阈值 $threshold%。"
    fi
}

while true; do
    cpu_usage=$(get_cpu_usage)
    mem_usage=$(get_mem_usage)
    disk_usage=$(get_disk_usage)
    rx_gb=$(get_rx_bytes)
    tx_gb=$(get_tx_bytes)

    check_and_message "$cpu_usage" "CPU" $cpu_threshold "$cpu_usage"
    check_and_message "$mem_usage" "内存" $mem_threshold "$mem_usage"
    check_and_message "$disk_usage" "硬盘" $disk_threshold "$disk_usage"

    # 检查入站流量是否超过阈值
    if (( $(echo "$rx_gb > $network_threshold_gb" | bc -l) )); then
        send_telegram_message "警告: ${isp_info}-${country}-${ip_masked} 的入站流量已达到 ${rx_gb}GB，超过阈值 ${network_threshold_gb}GB。"
    fi

    # 检查出站流量是否超过阈值
    if (( $(echo "$tx_gb > $network_threshold_gb" | bc -l) )); then
        send_telegram_message "警告: ${isp_info}-${country}-${ip_masked} 的出站流量已达到 ${tx_gb}GB，超过阈值 ${network_threshold_gb}GB。"
    fi

    # 休眠5分钟
    sleep 300
done