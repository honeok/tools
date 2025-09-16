#!/usr/bin/env bash
# vim:sw=4:ts=4:et
#
# Description: This script is used to automate the installation of the latest docker community edition (ce) on supported linux distributions.
#
# Copyright (c) 2023-2025 honeok <i@honeok.com>
#
# References:
# https://docs.docker.com/engine/install
#
# SPDX-License-Identifier: Apache-2.0

set -eE

# 当前脚本版本号
readonly VERSION='v25.9.17'

function _red { printf "\033[91m%b\033[0m\n" "$*"; }
function _green { printf "\033[92m%b\033[0m\n" "$*"; }
function _yellow { printf "\033[93m%b\033[0m\n" "$*"; }
function _purple { printf "\033[95m%b\033[0m\n" "$*"; }
function _cyan { printf "\033[96m%b\033[0m\n" "$*"; }
function _err_msg { printf "\033[41m\033[1mError\033[0m %b\n" "$*"; }
function _suc_msg { printf "\033[42m\033[1mSuccess\033[0m %b\n" "$*"; }
function _info_msg { printf "\033[43m\033[1mInfo\033[0m %b\n" "$*"; }

# 环境变量用于在debian或ubuntu操作系统中设置非交互式 (noninteractive) 安装模式
export DEBIAN_FRONTEND=noninteractive
# 设置PATH环境变量
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

# 设置系统utf-8语言环境
UTF8_LOCALE="$(locale -a 2>/dev/null | grep -iEm1 "UTF-8|utf8")"
[ -n "$UTF8_LOCALE" ] && export LC_ALL="$UTF8_LOCALE" LANG="$UTF8_LOCALE" LANGUAGE="$UTF8_LOCALE"

# 各变量默认值
OS_INFO="$(grep '^PRETTY_NAME=' /etc/os-release | awk -F'=' '{print $NF}' | sed 's#"##g')"
OS_NAME="$(grep '^ID=' /etc/os-release | awk -F'=' '{print $NF}' | sed 's#"##g')"

function _exit {
    local EXIT_CODE CURRENT_TIME RUNCOUNT TODAY TOTAL

    EXIT_CODE=$?
    CURRENT_TIME="$(date '+%Y-%m-%d %H:%M:%S %Z')"
    RUNCOUNT="$(curl -Ls https://hits.honeok.com/get-docker?action=hit)" # 脚本运行计数器
    TODAY="$(sed -n 's/.*"daily": *\([0-9]*\).*/\1/p' <<< "$RUNCOUNT")"
    TOTAL="$(sed -n 's/.*"total": *\([0-9]*\).*/\1/p' <<< "$RUNCOUNT")"

    _green "Current server time: $CURRENT_TIME Script completed."
    _purple "Thanks for using! More info: https://www.honeok.com"
    if [[ -n "$TODAY" && -n "$TOTAL" ]]; then
        echo "$(_yellow "Number of script runs today:") $(_cyan "$TODAY") $(_yellow "total number of script runs:") $(_cyan "$TOTAL")"
    fi
    exit "$EXIT_CODE"
}

trap '_exit' SIGINT SIGTERM EXIT

function clrscr {
    [ -t 1 ] && tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
}

function die {
    _err_msg >&2 "$(_red "$@")"; exit 1
}

function _exists {
    local _CMD="$1"
    if type "$_CMD" >/dev/null 2>&1; then return;
    elif command -v "$_CMD" >/dev/null 2>&1; then return;
    elif which "$_CMD" >/dev/null 2>&1; then return;
    else return 1;
    fi
}

# Logo from: https://www.lddgo.net/string/text-to-ascii-art (Small Slant)
function show_logo {
    _yellow "
  _____    __     __        __ 
 / ______ / /____/ ___ ____/ /_____ ____
/ (_ / -_/ __/ _  / _ / __/  '_/ -_/ __/
\___/\__/\__/\_,_/\___\__/_/\_\\__/_/
"
    _green "System   : $OS_INFO"
    echo "$(_yellow "Version  : $VERSION") $(_cyan "\xF0\x9F\x90\xB3")"
    echo
}

function check_root {
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
}

function check_bash {
    local BASH_VER

    # https://github.com/xykt/IPQuality/issues/28
    BASH_VER="$(bash --version | head -n1 | awk -F ' ' '{for (i=1; i<=NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+/) {print $i; exit}}' | cut -d . -f1)"
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

function curl {
    local RET
    # 添加 --fail 不然404退出码也为0
    # 32位cygwin已停止更新, 证书可能有问题, 添加 --insecure
    # centos7 curl 不支持 --retry-connrefused --retry-all-errors 因此手动 retry
    for ((i=1; i<=5; i++)); do
        command curl --connect-timeout 10 --fail --insecure "$@"
        RET=$?
        if [ "$RET" -eq 0 ]; then
            return
        else
            # 403 404 错误或达到重试次数
            if [ "$RET" -eq 22 ] || [ "$i" -eq 5 ]; then
                return "$RET"
            fi
            sleep 1
        fi
    done
}

function pkg_uninstall {
    for pkg in "$@"; do
        if _exists dnf; then
            dnf remove -y "$pkg"
        elif _exists yum; then
            yum remove -y "$pkg"
        elif _exists apt-get; then
            apt-get purge -y "$pkg"
        elif _exists apk; then
            apk del --no-network "$pkg"
        elif _exists pacman; then
            pacman -Rns --noconfirm "$pkg"
        else
            die "The package manager is not supported."
        fi
    done
}

function is_china {
    if [ -z "$COUNTRY" ]; then
        if ! COUNTRY="$(curl -Ls http://www.qualcomm.cn/cdn-cgi/trace | grep '^loc=' | cut -d= -f2 | grep .)"; then
            die "Can not get location."
        fi
        echo 2>&1 "Location: $COUNTRY"
    fi
    [ "$COUNTRY" = CN ]
}

function check_osVer {
    case "$OS_NAME" in
        debian)
            # 检查debian版本是否小于10
            if [ "$(grep -oE '[0-9]+' /etc/debian_version | head -1)" -lt 10 ]; then
                die "This version of Debian is no longer supported!"
            fi
        ;;
        ubuntu)
            # 检查ubuntu版本是否小于20.04
            if [ "$(grep "^VERSION_ID" /etc/os-release | cut -d '"' -f 2 | tr -d '.')" -lt '2004' ]; then
                die "This version of Ubuntu is no longer supported!"
            fi
        ;;
        centos)
            if [ "$(grep -shoE '[0-9]+' /etc/centos-release /etc/redhat-release | head -1)" -lt 7 ]; then
                die "This installer requires version $OS_NAME 7 or higher."
            fi
        ;;
        almalinux|rhel|rocky)
            # 检查almalinux/rhel/rocky版本是否小于8
            if [ "$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/redhat-release /etc/rocky-release | head -1)" -lt 8 ]; then
                die "This installer requires version $OS_NAME 8 or higher."
            fi
        ;;
        *)
            die "The current operating system is not supported!"
        ;;
    esac
}

function check_install {
    if _exists docker >/dev/null 2>&1 \
        || docker --version >/dev/null 2>&1 \
        || docker compose version >/dev/null 2>&1 \
        || _exists docker-compose >/dev/null 2>&1; then
        die "Docker is already installed. Exiting the installer."
    fi
}

function clear_repos {
    [ -f "/etc/yum.repos.d/docker-ce.repo" ] &&  rm -f /etc/yum.repos.d/docker-ce.repo >/dev/null 2>&1
    [ -f "/etc/yum.repos.d/docker-ce-staging.repo" ] &&  rm -f /etc/yum.repos.d/docker-ce-staging.repo >/dev/null 2>&1
    [ -f "/etc/apt/keyrings/docker.asc" ] &&  rm -f /etc/apt/keyrings/docker.asc >/dev/null 2>&1
    [ -f "/etc/apt/sources.list.d/docker.list" ] &&  rm -f /etc/apt/sources.list.d/docker.list >/dev/null 2>&1
}

function fix_dpkg {
    pkill -9 -f 'apt|dpkg' >/dev/null 2>&1
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock >/dev/null 2>&1
    dpkg --configure -a
}

function docker_install {
    local REPO_URL VERSION_CODE GPGKEY_URL

    _info_msg "$(_yellow 'Installing the Docker environment!')"
    echo
    if [ "$OS_NAME" = "almalinux" ] || [ "$OS_NAME" = "centos" ] || [ "$OS_NAME" = "rocky" ]; then
        pkg_uninstall docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine >/dev/null 2>&1

        if is_china; then
            REPO_URL="https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo"
        else
            REPO_URL="https://download.docker.com/linux/centos/docker-ce.repo"
        fi

        if _exists dnf >/dev/null 2>&1; then
            dnf config-manager --help >/dev/null 2>&1 || dnf install -y dnf-plugins-core
            dnf config-manager --add-repo "$REPO_URL" 2>/dev/null
            dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        elif _exists yum >/dev/null 2>&1; then
            rpm -q yum-utils >/dev/null 2>&1 || yum install -y yum-utils
            yum-config-manager --add-repo "$REPO_URL" >/dev/null 2>&1
            yum makecache fast
            yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        fi
    elif [ "$OS_NAME" = "rhel" ]; then
        pkg_uninstall docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine podman runc >/dev/null 2>&1

        dnf config-manager --help >/dev/null 2>&1 || dnf install -y dnf-plugins-core
        if is_china; then
            dnf config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/rhel/docker-ce.repo
        else
            dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
        fi
        dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    elif [ "$OS_NAME" = "debian" ] || [ "$OS_NAME" = "ubuntu" ]; then
        VERSION_CODE="$(grep "^VERSION_CODENAME" /etc/os-release | cut -d= -f2)"
        pkg_uninstall docker.io docker-doc docker-compose podman-docker containerd runc >/dev/null 2>&1

        if is_china; then
            REPO_URL="https://mirrors.aliyun.com/docker-ce/linux/$OS_NAME"
            GPGKEY_URL="https://mirrors.aliyun.com/docker-ce/linux/$OS_NAME/gpg"
        else
            REPO_URL="https://download.docker.com/linux/$OS_NAME"
            GPGKEY_URL="https://download.docker.com/linux/$OS_NAME/gpg"
        fi

        fix_dpkg
        apt-get -qq update
        apt-get install -y -qq ca-certificates curl
        install -m 0755 -d /etc/apt/keyrings
        curl -fLsS "$GPGKEY_URL" -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc

        # add the repository to apt sources
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] $REPO_URL $VERSION_CODE stable" |  tee /etc/apt/sources.list.d/docker.list >/dev/null
        apt-get -qq update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    else
        die "The current operating system is not supported!"
    fi

    systemctl daemon-reload
    systemctl enable docker --now
}

function check_status {
    if systemctl is-active --quiet docker \
        || docker info >/dev/null 2>&1 \
        || /etc/init.d/docker status | grep -q 'started' \
        || service docker status >/dev/null 2>&1 \
        || curl -s --unix-socket /var/run/docker.sock http://localhost/version >/dev/null 2>&1; then
        _suc_msg "$(_green 'Docker has completed self-check, started, and set to start on boot!')"
    else
        die "Docker status check failed or service not starting. Check logs or start Docker manually."
    fi
}

function docker_info {
    local DOCKER_V=""
    local COMPOSE_V=""

    # 获取Docker版本
    if _exists docker >/dev/null 2>&1; then
        DOCKER_V="$(docker --version | awk -F '[ ,]' '{print $3}')"
    elif _exists docker.io >/dev/null 2>&1; then
        DOCKER_V="$(docker.io --version | awk -F '[ ,]' '{print $3}')"
    fi

    # 获取Docker Compose版本
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_V="$(docker compose version --short)"
    elif _exists docker-compose >/dev/null 2>&1; then
        COMPOSE_V="$(docker-compose version --short)"
    fi

    echo
    echo "Docker Version: v$DOCKER_V"
    echo "Docker Compose Version: v$COMPOSE_V"
    echo
    _yellow "Get Docker information"
    sleep 2
    docker version 2>&1
}

clrscr
show_logo
check_root
check_bash
check_osVer

check_install
clear_repos
docker_install
check_status
docker_info