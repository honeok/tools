#!/usr/bin/env bash
#
# Description: Nginx container log rotation.
#
# Copyright (C) 2023 - 2025 honeok <honeok@duck.com>
#
# https://www.honeok.com
# https://github.com/honeok/Tools/raw/master/nginx/docker_ngx_rotate2.sh

work_dir=$(pwd)
log_dir="${work_dir}/log"
current_time=$(date +%Y-%m-%d)

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
gzip $log_dir/access_$current_time.log >/dev/null 2>&1
gzip $log_dir/error_$current_time.log >/dev/null 2>&1

# 删除7天前的日志
find $log_dir -type f -name "*.log.gz" -mtime +7 -exec rm {} \; >/dev/null 2>&1

exit 0
