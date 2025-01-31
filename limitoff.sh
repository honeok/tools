#!/usr/bin/env bash
#
# Description: Automatically shuts down the server when rate-limiting is triggered.
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

rx_threshold_gb=110
tx_threshold_gb=120

# 将GB转换为字节
rx_threshold=$((rx_threshold_gb * 1024 * 1024 * 1024))
tx_threshold=$((tx_threshold_gb * 1024 * 1024 * 1024))

# 获取总的接收流量和发送流量
rx_tx_data=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
    NR > 2 { rx_total += $2; tx_total += $10 }
    END {
        printf("%.0f %.0f", rx_total, tx_total);
    }' /proc/net/dev)

# 解析接收流量和发送流量数据
rx=$(echo "$rx_tx_data" | awk '{print $1}')
tx=$(echo "$rx_tx_data" | awk '{print $2}')

# 显示当前流量使用情况
echo "当前接收流量: $rx Bytes"
echo "当前发送流量: $tx Bytes"

# 检查是否达到接收流量阈值
if (( rx > rx_threshold )); then
    echo "接收流量达到${rx_threshold}，正在关闭服务器！"
    shutdown -h now
else
    echo "当前接收流量未达到${rx_threshold}，继续监视"
fi

# 检查是否达到发送流量阈值
if (( tx > tx_threshold )); then
    echo "发送流量达到${tx_threshold}，正在关闭服务器！"
    shutdown -h now
else
    echo "当前发送流量未达到${tx_threshold}，继续监视"
fi