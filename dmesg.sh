#!/usr/bin/env bash
#
# Description: Filters oom/kill from dmesg, computes absolute time, formats output.
#
# Copyright (C) 2025 honeok <honeok@duck.com>
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

_yellow() { printf "\033[93m%s\033[0m" "$*"; }

bootTime=$(date -d "$(uptime -s)" +%s)

dmesg | grep -i "oom\|kill" | while read -r entry; do
    # 提取时间戳
    timeStamp=$(echo "$entry" | awk -F'[][]' '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    # 时间戳为空跳过
    [ -z "$timeStamp" ] && continue

    # 计算事件绝对时间并格式化
    eventTimeSec=$((bootTime + $(echo "$timeStamp" | awk '{print int($1)}')))
    eventTime=$(date -d "@$eventTimeSec" "+%Y-%m-%d %H:%M:%S")

    echo "$(_yellow "Event Time: $eventTime") $entry"
done