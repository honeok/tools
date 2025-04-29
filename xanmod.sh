#!/usr/bin/env bash
#
# Description: one click script to install the XanMod kernel on debian/ubuntu systems.
#
# Copyright (c) 2024 - 2025 honeok <honeok@duck.com>
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

# https://www.graalvm.org/latest/reference-manual/ruby/UTF8Locale
export LANG=en_US.UTF-8

# 环境变量用于在Debian或Ubuntu操作系统中设置非交互式 (noninteractive) 安装模式
export DEBIAN_FRONTEND=noninteractive

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

_red() { printf "\033[91m%s\033[0m\n" "$*"; }
_green() { printf "\033[92m%s\033[0m\n" "$*"; }
_yellow() { printf "\033[93m%s\033[0m\n" "$*"; }
_err_msg() { printf "\033[41m\033[1mError\033[0m %s\n" "$*"; }
reading() { read -rep "$(_yellow "$1")" "$2"; }
separator() { printf "%-20s\n" "-" | sed 's/\s/-/g'; }

# 各变量默认值
OS_NAME="$(grep '^ID=' /etc/os-release | awk -F'=' '{print $NF}' | sed 's#"##g')"
GITHUB_PROXY='https://gh-proxy.com/'
CLOUDFLARE_API='www.qualcomm.cn'

declare -a CURL_OPTS=(--max-time 5 --retry 1 --retry-max-time 10)

clear_screen() {
    [ -t 1 ] && tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
}

_exists() {
    local _CMD="$1"
    if type "$_CMD" >/dev/null 2>&1; then
        return 0
    elif command -v "$_CMD" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

pkg_install() {
    for package in "$@"; do
        _yellow "Installing $package"
        if _exists apt-get; then
            apt-get update
            apt-get install -y -q "$package"
        elif _exists apt; then
            apt update
            apt install -y -q "$package"
        fi
    done
}

pkg_uninstall() {
    for package in "$@"; do
        if _exists apt-get; then
            apt-get purge -y "$package"
        elif _exists apt; then
            apt purge -y "$package"
        fi
    done
}

server_reboot() {
    local CHOICE
    reading '现在重启服务器吗? (y/n): ' CHOICE

    case "$CHOICE" in
        [Yy] | "" ) _green '已执行' ; reboot ;;
        *) : ; _yellow '已取消' ;;
    esac
}

# 运行预检
pre_check() {
    if [ "$EUID" -ne "0" ]; then
        _err_msg "$(_red '此脚本必须以root用户权限运行!')" && exit 1
    fi
    if [ "$(ps -p $$ -o comm=)" != "bash" ] || readlink /proc/$$/exe | grep -q "dash"; then
        _err_msg "$(_red '此脚本必须使用bash运行, 而非sh!')" && exit 1
    fi
    if [ "$OS_NAME" != "debian" ] && [ "$OS_NAME" != "ubuntu" ]; then
        _err_msg "$(_red '当前操作系统不受支持!')" && exit 1
    fi
    if [ "$(curl "${CURL_OPTS[@]}" -fsL -4 "http://$CLOUDFLARE_API/cdn-cgi/trace" | awk -F'=' '/^loc=/ {print $NF}' | xargs)" != "CN" ]; then
        unset GITHUB_PROXY
    fi
}

# 内核检查
kernel_check() {
    if _exists "hostnamectl"; then
        KERNEL_VERSION=$(hostnamectl | sed -n 's/^.*Kernel: Linux //p')
    else
        KERNEL_VERSION=$(uname -r)
    fi
}

# 检查系统架构
arch_check() {
    if [ "$(dpkg --print-architecture)" != 'amd64' ]; then
        _err_msg "$(_red '当前环境不被支持, 仅支持x86_64架构')" && exit 1
    fi
}

add_swap() {
    local NEW_SWAP="$1"

    # 创建并启用新的swap文件
    dd if=/dev/zero of=/swapfile bs=1M count="$NEW_SWAP" status=progress
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile

    # 更新fstab (避免重复添加)
    grep -q '/swapfile' /etc/fstab || echo "/swapfile swap swap defaults 0 0" >> /etc/fstab

    echo "虚拟内存大小已调整为: $(_green "$NEW_SWAP") MB"
}

check_swap() {
    local MEM_TOTAL SWAP_TOTAL
    MEM_TOTAL=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    SWAP_TOTAL=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)

    # 将KB转换为MB
    MEM_TOTAL=$((MEM_TOTAL / 1024))
    SWAP_TOTAL=$((SWAP_TOTAL / 1024))

    # 如果没有交换空间且物理内存≤900MB, 则创建1024MB交换空间
    if [ "$SWAP_TOTAL" -eq 0 ] && [ "$MEM_TOTAL" -le 900 ]; then
        add_swap 1024
    fi
}

# 用于检查并设置net.core.default_qdisc参数
set_default_qdisc() {
    local QDISC_CONTROL CONFIG_FILE CURRENT_VALUE CHOICE CHOSEN_QDISC
    QDISC_CONTROL="net.core.default_qdisc"
    CONFIG_FILE="/etc/sysctl.conf"

    # 使用grep查找现有配置, 忽略等号周围的空格, 排除注释行
    if grep -q "^[^#]*${QDISC_CONTROL}\s*=" "${CONFIG_FILE}"; then
        # 存在该设置项, 检查其值
        CURRENT_VALUE=$(grep "^[^#]*${QDISC_CONTROL}\s*=" "${CONFIG_FILE}" | sed -E "s/^[^#]*${QDISC_CONTROL}\s*=\s*(.*)/\1/")
        _yellow "当前队列规则为: $CURRENT_VALUE"
    else
        # 没有找到该设置项
        CURRENT_VALUE=""
    fi

    # 提供用户选择菜单
    while true; do
        echo "请选择要设置的队列规则"
        separator
        echo "1. fq (默认值): 基本的公平排队算法，旨在确保每个流获得公平的带宽分配，防止某个流占用过多带宽"
        echo "2. fq_pie      : 将FQ和PI (Proportional Integral) 控制结合在一起，旨在改善延迟和带宽利用率"
        echo "3. fq_codel    : 结合了公平排队和控制延迟的算法，通过主动丢包和公平分配带宽来减少延迟并提高多流的性能"
        separator
        reading '请输入选项并按回车键确认 (回车使用默认值: fq): ' CHOICE

        case "$CHOICE" in
            1|"") CHOSEN_QDISC="fq" ; break ;;
            2) CHOSEN_QDISC="fq_pie" ; break ;;
            3) CHOSEN_QDISC="fq_codel" ; break ;;
            *) _red '无效选项, 请重新输入' ;;
        esac
    done

    # 如果当前值不等于选择的值, 进行更新
    if [ "$CURRENT_VALUE" != "$CHOSEN_QDISC" ]; then
        if [ -z "$CURRENT_VALUE" ]; then
            # 如果没有设置项, 则新增
            echo "${QDISC_CONTROL}=${CHOSEN_QDISC}" >> "${CONFIG_FILE}"
        else
            # 如果设置项存在但值不匹配, 进行替换
            sed -i -E "s|^[^#]*${QDISC_CONTROL}\s*=\s*.*|${QDISC_CONTROL}=${CHOSEN_QDISC}|" "${CONFIG_FILE}"
        fi
        sysctl -p
        _green "队列规则已设置为: $CHOSEN_QDISC !"
    else
        _yellow "队列规则已经是 $CURRENT_VALUE ,无需更改"
    fi
}

bbr_on() {
    local CONGESTION_CONTROL="net.ipv4.tcp_congestion_control"
    local CONFIG_FILE="/etc/sysctl.conf"
    local CURRENT_VALUE

    CURRENT_VALUE=$(sysctl -n "$CONGESTION_CONTROL" 2>/dev/null)
    [ "$CURRENT_VALUE" = 'bbr' ] && return 0

    grep -q "^[^#]*${CONGESTION_CONTROL}" "$CONFIG_FILE" && 
        sed -i -E "s|^[^#]*${CONGESTION_CONTROL}\s*=\s*.*|${CONGESTION_CONTROL}=bbr|" "$CONFIG_FILE" || 
        echo "$CONGESTION_CONTROL=bbr" >> "$CONFIG_FILE"

    sysctl -p >/dev/null
    CURRENT_VALUE=$(sysctl -n "$CONGESTION_CONTROL" 2>/dev/null)
    [ "$CURRENT_VALUE" = 'bbr' ] && return 0
    _red "启用TCP BBR失败, 当前值为: $CURRENT_VALUE"
    return 1
}

xanmod_manager() {
    local XANMOD_VERSION CHOICE

    clear_screen
    if dpkg -l | grep -q 'linux-xanmod'; then
        while true; do
            _green '已安装XanMod的BBRv3内核'
            echo "当前内核版本: $KERNEL_VERSION"
            separator
            echo "1. 更新BBRv3内核              2. 卸载BBRv3内核"
            separator
            reading '请输入选项并按回车键确认: ' CHOICE

            case "$CHOICE" in
                1 | "" )
                    pkg_uninstall 'linux-*xanmod1*'
                    update-grub
                    # wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
                    curl -fsSL "${GITHUB_PROXY}https://github.com/kejilion/sh/raw/main/archive.key" | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
                    # 添加存储库
                    echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
                    # KERNEL_VERSION=$(wget -q https://dl.xanmod.org/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | sed -n 's/.*x86-64-v\([0-9]\+\).*/\1/p')
                    XANMOD_VERSION=$(curl -fsSL -O "${GITHUB_PROXY}https://github.com/kejilion/sh/raw/main/check_x86-64_psabi.sh" && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | awk -F 'x86-64-v' '{print $2+0}')
                    pkg_install "linux-xanmod-x64v$XANMOD_VERSION"
                    _green 'XanMod内核已更新, 重启后生效'
                    [ -f "/etc/apt/sources.list.d/xanmod-release.list" ] && rm -f /etc/apt/sources.list.d/xanmod-release.list
                    [ -f "check_x86-64_psabi.sh" ] && rm -f "check_x86-64_psabi.sh"
                    server_reboot && exit 0
                ;;
                2)
                    pkg_uninstall 'linux-*xanmod1*'
                    update-grub
                    _green 'XanMod内核已卸载, 重启后生效'
                    server_reboot && exit 0
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
        reading '确定继续吗? (y/n): ' CHOICE

        case "$CHOICE" in
            [Yy] | "" )
                check_swap
                pkg_install gnupg
                # wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
                curl -fsSL "${GITHUB_PROXY}https://github.com/kejilion/sh/raw/main/archive.key" | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
                # 添加存储库
                echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
                # KERNEL_VERSION=$(wget -q https://dl.xanmod.org/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | sed -n 's/.*x86-64-v\([0-9]\+\).*/\1/p')
                XANMOD_VERSION=$(curl -fsSL -O "${GITHUB_PROXY}https://github.com/kejilion/sh/raw/main/check_x86-64_psabi.sh" && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | awk -F 'x86-64-v' '{print $2+0}')
                pkg_install "linux-xanmod-x64v$XANMOD_VERSION"
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