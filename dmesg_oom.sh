#!/bin/bash

# 获取系统启动时间 (以秒为单位 相对于1970-01-01 00:00:00 UTC)
boot_time=$(date -d "$(uptime -s)" +%s)

# 使用dmesg获取日志并过滤处理每一行
dmesg | grep -i "oom\|kill" | while read -r entry; do
    # 提取时间戳
    timestamp=$(echo "$entry" | grep -oE '^\[[[:space:]]*[0-9]+\.[0-9]+\]' | tr -d '[] ')

    if [ -n "$timestamp" ]; then
        # 将时间戳转换为秒数 (取整数部分)
        event_time_sec=$(echo "$timestamp" | awk '{print int($1)}')

        # 计算事件发生的绝对时间 (启动时间 + 时间戳)
        absolute_time_sec=$((boot_time + event_time_sec))

        # 将绝对时间转换为可读的日期时间格式
        event_time=$(date -d "@$absolute_time_sec" "+%Y-%m-%d %H:%M:%S")

        echo "Event Time: $event_time | Log: $entry"
    fi
done