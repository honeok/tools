#!/usr/bin/env bash
#
# Description: automatically renew SSL certificates using Certbot in Docker.
#
# Forked and modified from Kejilion's script.
#
# Copyright (C) 2024 honeok <honeok@duck.com>

# 定义证书存储目录
certs_directory="/data/docker_data/certbot/cert/live/"

days_before_expiry=5  # 设置在证书到期前几天触发续签

short_separator() {
    printf "%-20s\n" "-" | sed 's/\s/-/g'
}

iptables_open() {
    local table
    for table in iptables ip6tables; do
        if ! command -v $table >/dev/null 2>&1; then
            continue
        fi

        $table -P INPUT ACCEPT >/dev/null 2>&1
        $table -P FORWARD ACCEPT >/dev/null 2>&1
        $table -P OUTPUT ACCEPT >/dev/null 2>&1
        $table -F >/dev/null 2>&1
    done
}

# 遍历所有证书文件
for cert_dir in $certs_directory*; do
    # 获取域名
    domain=$(basename "$cert_dir")

    # 忽略 README 目录
    if [ "$domain" = "README" ]; then
        continue
    fi

    # 输出正在检查的证书信息
    echo "检查证书过期日期:${domain}"

    # 获取fullchain.pem文件路径
    cert_file="${cert_dir}/fullchain.pem"

    # 获取证书过期日期
    expiration_date=$(openssl x509 -enddate -noout -in "${cert_file}" | cut -d "=" -f 2-)
    # 输出证书过期日期
    echo "过期日期:${expiration_date}"

    # 将日期转换为时间戳
    expiration_timestamp=$(date -d "${expiration_date}" +%s)
    current_timestamp=$(date +%s)

    # 计算距离过期还有几天
    days_until_expiry=$(( ($expiration_timestamp - $current_timestamp) / 86400 ))

    # 检查是否需要续签(在满足续签条件的情况下)
    if [ $days_until_expiry -le $days_before_expiry ]; then
        echo "证书将在${days_before_expiry}天内过期，正在进行自动续签"

        # 停止Nginx服务
        docker stop nginx > /dev/null 2>&1

        iptables_open 

        docker run -it --rm --name certbot \
            -p 80:80 -p 443:443 \
            -v "/data/docker_data/certbot/cert:/etc/letsencrypt" \
            -v "/data/docker_data/certbot/data:/var/lib/letsencrypt" \
            certbot/certbot certonly --standalone -d $domain --email honeok@email.com \
            --agree-tos --no-eff-email --force-renewal --key-type ecdsa

        \cp -rf /data/docker_data/certbot/cert/live/$domain/fullchain.pem /data/docker_data/web/nginx/certs/${domain}_cert.pem > /dev/null 2>&1
        \cp -rf /data/docker_data/certbot/cert/live/$domain/privkey.pem /data/docker_data/web/nginx/certs/${domain}_key.pem > /dev/null 2>&1

        openssl rand -out "/data/docker_data/web/nginx/certs/ticket12.key" 48
        openssl rand -out "/data/docker_data/web/nginx/certs/ticket13.key" 80

        docker start nginx >/dev/null 2>&1

        echo "证书已成功续签"
    else
        # 若未满足续签条件,则输出证书仍然有效
        echo "证书仍然有效,距离过期还有${days_until_expiry}天"
    fi

    short_separator
done