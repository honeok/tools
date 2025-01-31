#!/usr/bin/env bash
#
# Description: openssh high risk vulnerability repair.
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

export DEBIAN_FRONTEND=noninteractive

separator() { printf "%-15s\n" "-" | sed 's/\s/-/g'; }

if [ "$(cd -P -- "$(dirname -- "$0")" && pwd -P)" != "/root" ]; then
    cd /root >/dev/null 2>&1 || { echo '切换目录失败！'; return 1; }
fi

# 期望的ssh版本
desired_ssh_version="9.9p1"

# 获取操作系统类型
if [ -f /etc/os-release ]; then
    system_id=$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2}' /etc/os-release)
else
    echo "无法检测操作系统类型" && exit 1
fi

# 清理dpkg锁文件
fix_dpkg() {
    pkill -f -15 'apt|dpkg' || pkill -f -9 'apt|dpkg'
    for i in "/var/lib/dpkg/lock" "/var/lib/dpkg/lock-frontend"; do
        [ -f "$i" ] && rm -f "$i" >/dev/null 2>&1
    done
    dpkg --configure -a
}

# 安装依赖包
install_depend() {
    case $system_id in
        ubuntu|debian)
            fix_dpkg
            apt update && apt install -y build-essential zlib1g-dev libssl-dev libpam0g-dev wget ntpdate -o Dpkg::Options::="--force-confnew"
            ;;
        centos|rhel|almalinux|rocky|fedora)
            yum install -y epel-release
            yum groupinstall -y "Development Tools"
            yum install -y zlib-devel openssl-devel pam-devel wget ntpdate
            ;;
        alpine)
            apk add build-base zlib-dev openssl-dev pam-dev wget ntpdate
            ;;
        *)
            echo "不支持的操作系统: $system_id"
            exit 1
            ;;
    esac
}

install_openssh() {
    wget --no-check-certificate -q https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${desired_ssh_version}.tar.gz && \
    tar -xzvf openssh-${desired_ssh_version}.tar.gz && \
    cd openssh-${desired_ssh_version} && \
    ./configure && make && make install && \
    cd .. && rm -rf openssh-${desired_ssh_version} openssh-${desired_ssh_version}.tar.gz
}

restart_ssh() {
    case $system_id in
        ubuntu|debian)
            systemctl restart ssh
            ;;
        centos|rhel|almalinux|rocky|fedora)
            systemctl restart sshd
            ;;
        alpine)
            rc-service sshd restart
            ;;
        *)
            echo "不支持的操作系统：$system_id"
            exit 1
            ;;
    esac
}

# 设置路径优先级
set_path_priority() {
    local new_ssh_dir
    new_ssh_dir=$(dirname "$(which sshd)")

    if [[ ":$PATH:" != *":$new_ssh_dir:"* ]]; then
        export PATH="$new_ssh_dir:$PATH"
        echo "export PATH=\"$new_ssh_dir:\$PATH\"" >> ~/.bashrc
    fi
}

verify_installation() {
    separator
    echo "ssh版本信息:"
    separator
    ssh -V
    separator
    sshd -V
}

# 检查OpenSSH版本
main() {
    local current_version choice
    current_version=$(ssh -V 2>&1 | awk '{print $1}' | cut -d_ -f2 | cut -d'p' -f1)

    # 版本范围
    local min_version="8.5"
    local max_version="9.7"

    if awk -v ver="$current_version" -v min="$min_version" -v max="$max_version" \
        'BEGIN { if (ver >= min && ver <= max) exit 0; else exit 1 }'; then
        echo "当前ssh版本: $current_version 在8.5到9.7之间，需要修复！"
        echo -n "请输入(Y/n)并按回车键确认: "
        read -r choice

        case "$choice" in
            [yY][eE][sS] | [yY])
                install_depend
                install_openssh
                restart_ssh
                set_path_priority
                verify_installation
                ;;
            [nN][oO] | [nN])
                echo "已取消"
                exit 1
                ;;
            *)
                echo "无效选项，请重新输入"
                exit 1
                ;;
        esac
    else
        echo "当前ssh版本: $current_version 不在8.5到9.7之间，无需修复"
        exit 1
    fi
}

main