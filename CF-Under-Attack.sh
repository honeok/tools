#!/usr/bin/env bash
#
# Description: Automatically toggles Cloudflare's 5-second challenge based on website load every 5 minutes.
#
# Forked and modified from Kejilion's script.
#
# Copyright (C) 2024 honeok <honeok@duck.com>

email="AAAA"
api_key="BBBB"
zone_id="CCCC"
load_threshold=5.0  # 高负载阈值

telegram_bot_token="输入TG机器人API"
chat_id="输入TG用户ID"

# 发送Telegram通知
telegram_notify() {
    local message=$1
    curl -s -X POST "https://api.telegram.org/bot$telegram_bot_token/sendMessage" -d "chat_id=$chat_id" -d "text=$message"
}

# 获取当前系统负载
current_load=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1 | sed 's/^[ \t]*//;s/[ \t]*$//' || \
    (command -v w >/dev/null 2>&1 && w | head -1 | awk -F'load average:' '{print $2}' | cut -d, -f1 | sed 's/^[ \t]*//;s/[ \t]*$//' || \
    cat /proc/loadavg | awk '{print $1}'))

echo "当前系统负载: $current_load"

# 获取当前的Under Attack模式状态
status=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/settings/security_level" \
    -H "X-Auth-Email: $email" \
    -H "X-Auth-Key: $api_key" \
    -H "Content-Type: application/json" | jq -r '.result.value')

echo "当前的Under Attack模式状态: $status"

# 检查系统负载是否高于阈值
if (( $(echo "$current_load > $load_threshold" | bc -l) )); then
    if [ "$status" != "under_attack" ]; then
        echo "系统负载高于阈值，开启Under Attack模式"
        # telegram_notify "系统负载高于阈值，开启Under Attack模式"
        new_status="under_attack"
    else
        echo "系统负载高，但Under Attack模式已经开启"
        exit 0
    fi
else
    if [ "$status" == "under_attack" ]; then
        echo "系统负载低于阈值，关闭Under Attack模式"
        # telegram_notify "系统负载低于阈值，关闭Under Attack模式"
        new_status="high"
    else
        echo "系统负载低，Under Attack模式已经关闭"
        exit 0
    fi
fi

# 更新Under Attack模式状态
response=$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_id/settings/security_level" \
    -H "X-Auth-Email: $email" \
    -H "X-Auth-Key: $api_key" \
    -H "Content-Type: application/json" \
    --data "{\"value\":\"$new_status\"}")

if [[ $(echo $response | jq -r '.success') == "true" ]]; then
    echo "成功更新Under Attack模式状态为: $new_status"
else
    echo "更新Under Attack模式状态失败"
    echo "响应: $response"
fi