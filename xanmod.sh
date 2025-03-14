#!/usr/bin/env bash
#
# Description: one-click script to install the XanMod kernel on debian/ubuntu systems.
#
# Copyright (C) 2024 - 2025 honeok <honeok@duck.com>
#
# References:
# https://xanmod.org
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

red='\033[91m'
green='\033[92m'
yellow='\033[93m'
white='\033[0m'
_red() { echo -e "${red}$*${white}"; }
_green() { echo -e "${green}$*${white}"; }
_yellow() { echo -e "${yellow}$*${white}"; }

_err_msg() { echo -e "\033[41m\033[1mError${white} $*"; }

separator() { printf "%-20s\n" "-" | sed 's/\s/-/g'; }
reading() { read -rep "$(_yellow "$1")" "$2"; }

os_name=$(grep "^ID=" /etc/*-release | awk -F'=' '{print $2}' | sed 's/"//g')
github_Proxy='https://gh-proxy.com/'

export DEBIAN_FRONTEND=noninteractive

clear_screen() {
    if [ -t 1 ]; then
        tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
    fi
}

_exists() {
    local cmd="$1"
    if type "$cmd" >/dev/null 2>&1; then
        return 0
    elif command -v "$cmd" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

pkg_install() {
    for package in "$@"; do
        _yellow "Installing $package"
        if _exists apt; then
            apt install -y -q "$package"
        elif _exists apt-get; then
            apt-get install -y -q "$package"
        fi
    done
}

pkg_uninstall() {
    for package in "$@"; do
        if _exists apt; then
            apt purge -y "$package"
        elif _exists apt-get; then
            apt-get purge -y "$package"
        fi
    done
}

server_reboot() {
    local choice
    reading '现在重启服务器吗? (y/n): ' choice

    case "$choice" in
        [Yy]) _green '已执行' ; reboot ;;
        *) : ; _yellow '已取消' ;;
    esac
}

# 运行预检
pre_check() {
    if [ "$(id -ru)" -ne "0" ] || [ "$EUID" -ne "0" ]; then
        _err_msg "$(_red '此脚本必须以root用户权限运行!')" && exit 1
    fi
    if [ "$(ps -p $$ -o comm=)" != "bash" ] || readlink /proc/$$/exe | grep -q "dash"; then
        _err_msg "$(_red '此脚本必须使用bash运行, 而非sh!')" && exit 1
    fi
    if [ "$os_name" != "debian" ] || [ "$os_name" != "ubuntu" ]; then
        _err_msg "$(_red '当前操作系统不受支持!')" && exit 1
    fi
    if [ "$(curl -fskL -m 3 -4 'https://www.qualcomm.cn/cdn-cgi/trace' | grep -i '^loc=' | cut -d'=' -f2 | xargs)" = 'CN' ]; then
        github_Proxy=''
    fi
}

# 内核检查
kernel_check() {
    if _exists "hostnamectl"; then
        kernel_version=$(hostnamectl | sed -n 's/^.*Kernel: Linux //p')
    else
        kernel_version=$(uname -r)
    fi
}

# 检查系统架构
arch_check() {
    if [ "$(dpkg --print-architecture)" != 'amd64' ]; then
        _err_msg "$(_red '当前环境不支持, 仅支持x86_64架构')" && exit 1
    fi
}

add_swap() {
    local new_swap="$1"
    local swap_partitions
    swap_partitions=$(grep '^/dev/' /proc/swaps | awk '{print $1}')

    # 禁用并重置所有 swap 分区
    for partition in $swap_partitions; do
        swapoff "$partition" >/dev/null 2>&1
        wipefs -a "$partition" >/dev/null 2>&1
        mkswap -f "$partition" >/dev/null 2>&1
    done

    # 清理旧的 swapfile
    swapoff /swapfile >/dev/null 2>&1
    [ -f /swapfile ] && rm -f /swapfile

    # 创建并启用新的swap文件
    dd if=/dev/zero of=/swapfile bs=1M count="$new_swap" status=progress
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile

    # 更新fstab (避免重复添加)
    if ! grep '/swapfile' /etc/fstab >/dev/null; then
        echo "/swapfile swap swap defaults 0 0" | tee -a /etc/fstab >/dev/null
    fi

    if [ -f /etc/alpine-release ]; then
        echo "nohup swapon /swapfile" > /etc/local.d/swap.start
        chmod +x /etc/local.d/swap.start
        rc-update add local >/dev/null 2>&1
    fi

    _green "虚拟内存大小已调整为: $new_swap MB"
}

check_swap() {
    local swap_total mem_total
    read -r _ _ mem_total _ < <(grep MemTotal /proc/meminfo)
    read -r _ _ swap_total _ < <(grep SwapTotal /proc/meminfo)

    # 将KB转换为MB
    mem_total=$((mem_total / 1024))
    swap_total=$((swap_total / 1024))

    # 如果没有交换空间且物理内存≤900MB, 则创建1024MB交换空间
    if ((swap_total == 0 && mem_total <= 900)); then
        add_swap 1024
    fi
}

# 用于检查并设置net.core.default_qdisc参数
set_default_qdisc() {
    local qdisc_control config_file current_value choice chosen_qdisc
    qdisc_control="net.core.default_qdisc"
    config_file="/etc/sysctl.conf"

    # 使用grep查找现有配置, 忽略等号周围的空格, 排除注释行
    if grep -q "^[^#]*${qdisc_control}\s*=" "${config_file}"; then
        # 存在该设置项, 检查其值
        current_value=$(grep "^[^#]*${qdisc_control}\s*=" "${config_file}" | sed -E "s/^[^#]*${qdisc_control}\s*=\s*(.*)/\1/")
        _yellow "当前队列规则为: $current_value"
    else
        # 没有找到该设置项
        current_value=""
    fi

    # 提供用户选择菜单
    while true; do
        echo "请选择要设置的队列规则"
        separator
        echo "1. fq (默认值): 基本的公平排队算法，旨在确保每个流获得公平的带宽分配，防止某个流占用过多带宽"
        echo "2. fq_pie      : 将FQ和PI (Proportional Integral) 控制结合在一起，旨在改善延迟和带宽利用率"
        echo "3. fq_codel    : 结合了公平排队和控制延迟的算法，通过主动丢包和公平分配带宽来减少延迟并提高多流的性能"
        separator
        reading '请输入选项并按回车键确认 (回车使用默认值: fq): ' choice

        case "$choice" in
            1|"") chosen_qdisc="fq" ; break ;;
            2) chosen_qdisc="fq_pie" ; break ;;
            3) chosen_qdisc="fq_codel" ; break ;;
            *) _red '无效选项, 请重新输入' ;;
        esac
    done

    # 如果当前值不等于选择的值, 进行更新
    if [ "$current_value" != "$chosen_qdisc" ]; then
        if [ -z "$current_value" ]; then
            # 如果没有设置项, 则新增
            echo "${qdisc_control}=${chosen_qdisc}" >> "${config_file}"
        else
            # 如果设置项存在但值不匹配, 进行替换
            sed -i -E "s|^[^#]*${qdisc_control}\s*=\s*.*|${qdisc_control}=${chosen_qdisc}|" "${config_file}"
        fi
        sysctl -p
        _green "队列规则已设置为: $chosen_qdisc !"
    else
        _yellow "队列规则已经是 $current_value ,无需更改"
    fi
}

bbr_on() {
    local congestion_control="net.ipv4.tcp_congestion_control"
    local config_file="/etc/sysctl.conf"
    local current_value

    current_value=$(sysctl -n "$congestion_control" 2>/dev/null)
    [ "$current_value" = 'bbr' ] && return 0

    grep -q "^[^#]*${congestion_control}" "$config_file" && 
        sed -i -E "s|^[^#]*${congestion_control}\s*=\s*.*|${congestion_control}=bbr|" "$config_file" || 
        echo "$congestion_control=bbr" >> "$config_file"

    sysctl -p >/dev/null
    current_value=$(sysctl -n "$congestion_control" 2>/dev/null)
    [ "$current_value" = 'bbr' ] && return 0
    _red "启用TCP BBR失败, 当前值为: $current_value"
    return 1
}

xanmod_manager() {
    local xanmod_version choice

    clear_screen
    if dpkg -l | grep -q 'linux-xanmod'; then
        while true; do
            _green '已安装XanMod的BBRv3内核'
            echo "当前内核版本: $kernel_version"
            separator
            echo "1. 更新BBRv3内核              2. 卸载BBRv3内核"
            separator
            reading '请输入选项并按回车键确认: ' choice

            case "$choice" in
                1)
                    pkg_uninstall 'linux-*xanmod1*'
                    update-grub
                    # wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
                    curl -fskL "${github_Proxy}https://github.com/kejilion/sh/raw/main/archive.key" | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
                    # 添加存储库
                    echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
                    # kernel_version=$(wget -q https://dl.xanmod.org/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | sed -n 's/.*x86-64-v\([0-9]\+\).*/\1/p')
                    xanmod_version=$(curl -fskL -O "${github_Proxy}https://github.com/kejilion/sh/raw/main/check_x86-64_psabi.sh" && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | awk -F 'x86-64-v' '{print $2+0}')
                    pkg_install linux-xanmod-x64v"$xanmod_version"
                    _green 'XanMod内核已更新, 重启后生效'
                    [ -f "/etc/apt/sources.list.d/xanmod-release.list" ] && rm -f /etc/apt/sources.list.d/xanmod-release.list
                    [ -f "check_x86-64_psabi.sh" ] && rm -f "check_x86-64_psabi.sh"
                    server_reboot
                ;;
                2)
                    pkg_uninstall 'linux-*xanmod1*'
                    update-grub
                    _green 'XanMod内核已卸载, 重启后生效'
                    server_reboot
                ;;
                0)
                    break
                ;;
                *)
                    _red '无效选项, 请重新输入'
                ;;
            esac
        done
    else
        clear_screen
        echo "请备份数据, 将为你升级Linux内核开启 $(_yellow 'XanMod BBR3')"
        separator
        echo "仅支持Debian/Ubuntu并且仅支持x86_64架构"
        echo "请备份数据, 将为你升级Linux内核开启BBR3!"
        separator
        reading '确定继续吗? (y/n): ' choice

        case "$choice" in
            [Yy])
                check_swap
                pkg_install gnupg
                # wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
                curl -fskL "${github_Proxy}https://github.com/kejilion/sh/raw/main/archive.key" | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
                # 添加存储库
                echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
                # kernel_version=$(wget -q https://dl.xanmod.org/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | sed -n 's/.*x86-64-v\([0-9]\+\).*/\1/p')
                xanmod_version=$(curl -fskL -O "${github_Proxy}https://github.com/kejilion/sh/raw/main/check_x86-64_psabi.sh" && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | awk -F 'x86-64-v' '{print $2+0}')
                pkg_install linux-xanmod-x64v"$xanmod_version"
                set_default_qdisc
                bbr_on
                _green 'XanMod内核安装并启用BBR3成功, 重启后生效!'
                [ -f "/etc/apt/sources.list.d/xanmod-release.list" ] && rm -f /etc/apt/sources.list.d/xanmod-release.list
                [ -f "check_x86-64_psabi.sh" ] && rm -f "check_x86-64_psabi.sh"
                server_reboot
            ;;
            [Nn])
                :
                _yellow "已取消"
            ;;
            *)
                _red "无效选项, 请重新输入"
            ;;
        esac
    fi
}

xanmod() {
    pre_check
    kernel_check
    arch_check
    xanmod_manager
}

xanmod