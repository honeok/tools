#!/usr/bin/env bash
#
# Description: Automates the backup process of website data for the LDNMP (Linux, Docker, Nginx, MySQL, PHP) stack.
#              This script ensures the regular backup of web-related files, protecting the integrity of the website's data.
#
# Copyright (C) 2024 - 2025 honeok <honeok@duck.com>
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

# 切换到web目录并创建归档
cd /data/docker_data/web && tar czvf "web_$(date +"%Y%m%d%H%M%S").tar.gz" .

# 将归档传输到另一台VPS的/opt目录
find . -name "*.tar.gz" -type f -print0 | xargs -0 ls -1t | head -n 1 | xargs -0 -I {} sshpass -p 123456 scp -o StrictHostKeyChecking=no -P 22 {} root@0.0.0.0:/opt/

# 保留最新的5个归档，删除其余的
find . -name "*.tar.gz" -type f -print0 | xargs -0 ls -1t | tail -n +6 | xargs -0 rm -f