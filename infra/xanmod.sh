#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Description: The script installs the high performance xanmod kernel on debian based systems.
# Copyright (c) 2025-2026 honeok <i@honeok.com>
#                                <honeok7@gmail.com>

# References:
# https://github.com/bin456789/reinstall
# https://github.com/mlocati/docker-php-extension-installer

set -eE

# shellcheck disable=SC2034
readonly SCRIPT_VERSION='v26.1.3'

# 强制linux输出英文
# https://www.gnu.org/software/gettext/manual/html_node/The-LANGUAGE-variable.html
export LC_ALL=C

# 设置PATH环境变量
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

# 环境变量用于在debian或ubuntu操作系统中设置非交互式 (noninteractive) 安装模式
export DEBIAN_FRONTEND=noninteractive

if [ "$GITHUB_ACTIONS" = "true" ] || [ "$HOME" = "/home/runner" ]; then
    GITHUB_CI=1
fi

# https://github.com/deater/linux_logo
linux_logo() {
    printf "%b" "\
                                                                 #####
                                                                #######
                   @                                            ##O#O##
  ######          @@#                                           #VVVVV#
    ##             #                                          ##  VVV  ##
    ##         @@@   ### ####   ###    ###  ##### ######     #          ##
    ##        @  @#   ###    ##  ##     ##    ###  ##       #            ##
    ##       @   @#   ##     ##  ##     ##      ###         #            ###
    ##          @@#   ##     ##  ##     ##      ###        QQ#           ##Q
    ##       # @@#    ##     ##  ##     ##     ## ##     QQQQQQ#       #QQQQQQ
    ##      ## @@# #  ##     ##  ###   ###    ##   ##    QQQQQQQ#     #QQQQQQQ
  ############  ###  ####   ####   #### ### ##### ######   QQQQQ#######QQQQQ

       Linux Version $(uname -r 2>/dev/null), Compiled $(uname -v 2>/dev/null | awk '{print $1,$2,$3}')
"
}

clear() {
    [ -t 1 ] && tput clear 2>/dev/null || printf "\033[2J\033[H" || command clear
}

die() {
    local EXIT_CODE
    EXIT_CODE="${2:-1}"

    printf >&2 'Error: %s\n' "$1"
    exit "$EXIT_CODE"
}

show_usage() {
    tee >&2 <<'EOF'
Usage: ./xanmod.sh

Options:
    -h, --help      Show this help message and exit
    -x, --debug     Enable debug mode (set -x)
    --ci            Force CI mode (skip grub update, use mirror URLs)
EOF
    exit 1
}

get_cmd_path() {
    # -f: 忽略shell内置命令和函数, 只考虑外部命令
    # -p: 只输出外部命令的完整路径
    type -f -p "$1"
}

is_have_cmd() {
    get_cmd_path "$1" >/dev/null 2>&1
}

check_root() {
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
}

check_bash() {
    local BASH_VER
    BASH_VER="$(bash --version 2>&1 | head -n1 | awk -F ' ' '{for (i=1; i<=NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+/) {print $i; exit}}' | cut -d . -f1)"

    if [ -z "$BASH_VERSION" ]; then
        die "This script needs to be run with bash, not sh!"
    fi
    if [ -z "$BASH_VER" ] || ! [[ "$BASH_VER" =~ ^[0-9]+$ ]]; then
        die "Failed to parse Bash version!"
    fi
    if [ "$BASH_VER" -lt 4 ]; then
        die "Bash version is lower than 4.0!"
    fi
}

check_arch() {
    if [ -z "$OS_ARCH" ]; then
        case "$(uname -m 2>/dev/null)" in
        amd64 | x86_64) OS_ARCH="amd64" ;;
        *) die "This architecture is not supported." ;;
        esac
    fi

    echo >&1 "Architecture: $OS_ARCH"
}

check_vir() {
    if is_have_cmd systemd-detect-virt; then
        if systemd-detect-virt -qc; then
            die "Not supported os in container."
        fi
    else
        if [ -d /proc/vz ] || grep -q container=lxc /proc/1/environ; then
            die "Not supported os in container."
        fi
    fi
}

load_os_info() {
    if [ ! -r /etc/os-release ]; then
        die "The file /etc/os-release is not readable."
    fi
    # shellcheck source=/dev/null
    . /etc/os-release
}

install_pkg() {
    for pkg in "$@"; do
        if is_have_cmd dnf; then
            dnf install -y "$pkg"
        elif is_have_cmd yum; then
            yum install -y "$pkg"
        elif is_have_cmd apt-get; then
            apt-get update
            apt-get install -y -q "$pkg"
        else
            die "The package manager is not supported."
        fi
    done
}

curl() {
    local EXIT_CODE

    is_have_cmd curl || install_pkg curl

    # --fail             4xx/5xx返回非0
    # --insecure         兼容旧平台证书问题
    # --connect-timeout  连接超时保护
    # CentOS7 无法使用 --retry-connrefused 和 --retry-all-errors 因此手动 retry

    for ((i = 1; i <= 5; i++)); do
        if ! command curl --connect-timeout 10 --fail --insecure "$@"; then
            EXIT_CODE=$?
            # 403 404 错误或达到重试次数
            if [ "$EXIT_CODE" -eq 22 ] || [ "$i" -eq 5 ]; then
                return "$EXIT_CODE"
            fi
            sleep 1
        else
            return
        fi
    done
}

# debian/ubuntu
# https://xanmod.org
xanmod_install() {
    local XANMOD_URL XANMOD_CHECK_SCRIPT XANMOD_KEY XANMOD_VERSION XANMOD_KEYRING XANMOD_APTLIST

    if [ "$GITHUB_CI" = 1 ]; then
        XANMOD_CHECK_SCRIPT="https://github.com/yumaoss/My_tools/raw/main/check_x86-64_psabi.sh"
        XANMOD_KEY="https://github.com/yumaoss/My_tools/raw/main/archive.key"
    else
        XANMOD_URL="dl.xanmod.org"
        XANMOD_CHECK_SCRIPT="https://$XANMOD_URL/check_x86-64_psabi.sh"
        XANMOD_KEY="https://$XANMOD_URL/archive.key"
    fi

    # https://gitlab.com/xanmod/linux
    XANMOD_VERSION="$(curl -L "$XANMOD_CHECK_SCRIPT" | awk -f - 2>/dev/null | awk -F 'x86-64-v' '{v=$2+0; if(v==4)v=3; print v}')"
    XANMOD_KEYRING="/etc/apt/keyrings/xanmod-archive-keyring.gpg"
    XANMOD_APTLIST="/etc/apt/sources.list.d/xanmod-release.list"

    dpkg -s gnupg >/dev/null 2>&1 || install_pkg gnupg
    curl -L "$XANMOD_KEY" | gpg --dearmor -vo "$XANMOD_KEYRING"
    echo "deb [signed-by=$XANMOD_KEYRING] http://deb.xanmod.org $VERSION_CODENAME main" | tee "$XANMOD_APTLIST"
    if [[ -n "$XANMOD_VERSION" && "$XANMOD_VERSION" =~ ^[0-9]$ ]]; then
        install_pkg "linux-xanmod-x64v$XANMOD_VERSION"
    else
        die "Failed to get XanMod version."
    fi
    rm -f "$XANMOD_APTLIST" || true
    [ "$GITHUB_CI" = 1 ] || update-grub
}

## 主程序入口
clear
linux_logo
check_root
check_bash
check_arch # 检查架构 仅支持amd64
check_vir  # 不支持容器虚拟化
load_os_info

while [ "$#" -gt 0 ]; do
    case "$1" in
    -h | --help)
        show_usage
        shift
        ;;
    -x | --debug)
        set -x
        shift 1
        ;;
    --ci)
        GITHUB_CI=1
        shift 1
        ;;
    *)
        echo "Unexpected option: $1."
        show_usage
        ;;
    esac
done

xanmod_install
