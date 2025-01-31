#!/usr/bin/env bash
#
# Description: Log rotation script for Nginx container logs to manage log size and retention.
#
# Copyright (C) 2023 - 2025 honeok <honeok@duck.com>
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

work_dir=$(pwd)
log_dir="${work_dir}/log"
current_time=$(date -u '+%Y-%m-%d' -d '+8 hours')

bark_apikey=""

if [ -d "$log_dir" ] && [ -n "$(ls -A "$log_dir" 2>/dev/null)" ]; then
    mv "$log_dir/access.log" "$log_dir/access_$current_time.log" >/dev/null 2>&1
    mv "$log_dir/error.log" "$log_dir/error_$current_time.log" >/dev/null 2>&1
else
    echo "error: The log does not exist" >&2
    exit 1
fi

# 向Nginx发送信号，重新打开日志文件
docker exec nginx nginx -s reopen >/dev/null 2>&1

# 压缩旧日志
gzip "$log_dir"/access_"$current_time".log >/dev/null 2>&1
gzip "$log_dir"/error_"$current_time".log >/dev/null 2>&1

# 删除7天前的日志
find "$log_dir" -type f -name "*.log.gz" -mtime +7 -exec rm -f {} \; >/dev/null 2>&1

if [ -n "$bark_apikey" ]; then
    curl -fsL -o /dev/null "https://api.day.app/$bark_apikey/Nginx/$(hostname)日志完成切割"
fi