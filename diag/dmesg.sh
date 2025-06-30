#!/usr/bin/env bash
#
# Description: This script is used to filter oom/kill events from dmesg, calculate absolute time and format output.
#
# Copyright (c) 2025 honeok <honeok@disroot.org>
#
# SPDX-License-Identifier: Apache-2.0

set -eE

_yellow() { printf "\033[93m%b\033[0m" "$*"; }

# 获取系统启动时间
BOOTTIME="$(date -d "$(uptime -s)" +%s 2>/dev/null || awk '/btime/ {print $2}' /proc/stat 2>/dev/null)"

dmesg | grep -i "oom\|kill" | while read -r ENTRY; do
    # 提取时间戳
    TIMESTAMP="$(echo "$ENTRY" | awk -F'[][]' '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    # 时间戳为空跳过
    [ -z "$TIMESTAMP" ] && continue

    # 计算事件绝对时间并格式化
    EVENTTIMESEC="$((BOOTTIME + $(echo "$TIMESTAMP" | awk '{print int($1)}')))"
    EVENTTIME="$(date -d "@$EVENTTIMESEC" "+%Y-%m-%d %H:%M:%S")"

    echo "$(_yellow "Event Time: $EVENTTIME") $ENTRY"
done