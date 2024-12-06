#!/bin/bash

LOG_DIR="/data/docker_data/nginx/log"
DATE=$(date +%Y-%m-%d)

# 切割日志
mv $LOG_DIR/access.log $LOG_DIR/access_$DATE.log > /dev/null 2>&1
mv $LOG_DIR/error.log $LOG_DIR/error_$DATE.log > /dev/null 2>&1

# 向Nginx发送信号，重新打开日志文件
docker exec nginx nginx -s reopen > /dev/null 2>&1

# 压缩旧日志
gzip $LOG_DIR/access_$DATE.log > /dev/null 2>&1
gzip $LOG_DIR/error_$DATE.log > /dev/null 2>&1

# 删除7天前的日志
find $LOG_DIR -type f -name "*.log.gz" -mtime +7 -exec rm {} \; > /dev/null 2>&1

# BarkAPI 通知日志轮换过程完成
# curl -s -o /dev/null "https://api.honeok.de/to73XJ2pqf6HfHMg8XXXXX/Nginx/日志完成切割"

exit 0
