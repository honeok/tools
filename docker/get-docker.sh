#!/usr/bin/env bash
# vim:sw=4:ts=4:et
#
# Description: This script installs the latest version of Docker Community Edition (CE) on supported Linux distributions.
#
# Copyright (c) 2023-2025 honeok <honeok@disroot.org>
#
# References:
# https://docs.docker.com/engine/install
#
# SPDX-License-Identifier: Apache-2.0

# 当前脚本版本号
readonly VERSION='v0.1.6 (2025.04.27)'

# https://www.graalvm.org/latest/reference-manual/ruby/UTF8Locale
export LANG=en_US.UTF-8

# 环境变量用于在Debian或Ubuntu操作系统中设置非交互式 (noninteractive) 安装模式
export DEBIAN_FRONTEND=noninteractive

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

function _red { printf "\033[91m%s\033[0m\n" "$*"; }
function _green { printf "\033[92m%s\033[0m\n" "$*"; }
function _yellow { printf "\033[93m%s\033[0m\n" "$*"; }
function _purple { printf "\033[95m%s\033[0m\n" "$*"; }
function _cyan { printf "\033[96m%s\033[0m\n" "$*"; }

function _err_msg { printf "\033[41m\033[1mError\033[0m %s\n" "$*"; }
function _suc_msg { printf "\033[42m\033[1mSuccess\033[0m %s\n" "$*"; }
function _info_msg { printf "\033[43m\033[1mInfo\033[0m %s\n" "$*"; }

# 各变量默认值
GETDOCKER_PID='/tmp/getdocker.pid'
OS_INFO="$(grep '^PRETTY_NAME=' /etc/os-release | awk -F'=' '{print $NF}' | sed 's#"##g')"
OS_NAME="$(grep '^ID=' /etc/os-release | awk -F'=' '{print $NF}' | sed 's#"##g')"
UA_BROWSER='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'

# curl默认参数
declare -a CURL_OPTS=(--max-time 5 --retry 1 --retry-max-time 10)

if [ -f "$GETDOCKER_PID" ] && kill -0 "$(cat "$GETDOCKER_PID")" 2>/dev/null; then
    _err_msg "$(_red 'The script seems to be running, please do not run it again!')" && exit 1
fi

function _exit {
    local RETURN_VALUE="$?"

    [ -f "$GETDOCKER_PID" ] && rm -f "$GETDOCKER_PID" 2>/dev/null
    exit "$RETURN_VALUE"
}

trap '_exit' SIGINT SIGQUIT SIGTERM EXIT

echo $$ > "$GETDOCKER_PID"

# Logo generation from: https://www.lddgo.net/string/text-to-ascii-art (Small Slant)
function show_logo {
    local YELLOW
    YELLOW='\033[93m'

    echo -e "$YELLOW  _____    __     __        __ 
 / ______ / /____/ ___ ____/ /_____ ____
/ (_ / -_/ __/ _  / _ / __/  '_/ -_/ __/
\___/\__/\__/\_,_/\___\__/_/\_\\__/_/
"
    _green "System   : $OS_INFO"
    echo "$(_yellow "Version  : $VERSION") $(printf '\033[95m\xF0\x9F\x90\xB3\033[0m\n')"
    _cyan 'bash <(curl -sL https://github.com/honeok/tools/raw/master/script/get-docker.sh)'
    printf '\n'
}

# 清屏函数
function clear_screen {
    [ -t 1 ] && tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
}

function _exists {
    local _CMD="$1"
    if type "$_CMD" >/dev/null 2>&1; then
        return 0
    elif command -v "$_CMD" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

function runtime_count {
    local RUNCOUNT
    RUNCOUNT=$(curl -A "$UA_BROWSER" "${CURL_OPTS[@]}" -fsL -k "http://hits.honeok.com/get-docker?action=hit")
    TODAY=$(echo "$RUNCOUNT" | grep '"daily"' | sed 's/.*"daily": *\([0-9]*\).*/\1/')
    TOTAL=$(echo "$RUNCOUNT" | grep '"total"' | sed 's/.*"total": *\([0-9]*\).*/\1/')
}

function end_message {
    local CURRENT_TIME
    CURRENT_TIME=$(date '+%Y-%m-%d %H:%M:%S %Z')

    runtime_count
    _green "Current server time: $CURRENT_TIME Script completed."
    _purple "Thanks for using! More info: https://www.honeok.com"
    if [ -n "$TODAY" ] && [ -n "$TOTAL" ]; then
        echo "$(_yellow 'Number of script runs today:') $(_cyan "$TODAY") $(_yellow 'total number of script runs:') $(_cyan "$TOTAL")"
    fi
}

function pre_check {
    # 备用 www.prologis.cn
    # 备用 www.autodesk.com.cn
    # 备用 www.keysight.com.cn
    CLOUDFLARE_API='www.qualcomm.cn'

    if [ "$(id -ru)" -ne 0 ] || [ "$EUID" -ne 0 ]; then
        _err_msg "$(_red 'This script must be run as root!')" && exit 1
    fi
    if [ "$(ps -p $$ -o comm=)" != "bash" ] || readlink /proc/$$/exe | grep -q "dash"; then
        _err_msg "$(_red 'This script needs to be run with bash, not sh!')" && exit 1
    fi
    COUNTRY=$(curl -A "$UA_BROWSER" "${CURL_OPTS[@]}" -fsL -k "http://$CLOUDFLARE_API/cdn-cgi/trace" | grep -i '^loc=' | cut -d'=' -f2 | xargs)
    [ -z "$COUNTRY" ] && _err_msg "$(_red 'Cannot retrieve server location. Check your network and try again.')" && end_message && exit 1
}

function os_permission {
    case "$OS_NAME" in
        'debian')
            # 检查debian版本是否小于10
            if [ "$(grep -oE '[0-9]+' /etc/debian_version | head -1)" -lt 10 ]; then
                _err_msg "$(_red 'This version of Debian is no longer supported!')" && end_message && exit 1
            fi
        ;;
        'ubuntu')
            # 检查ubuntu版本是否小于20.04
            if [ "$(grep "^VERSION_ID" /etc/os-release | cut -d '"' -f 2 | tr -d '.')" -lt '2004' ]; then
                _err_msg "$(_red 'This version of Ubuntu is no longer supported!')" && end_message && exit 1
            fi
        ;;
        'centos')
            if [ "$(grep -shoE '[0-9]+' /etc/centos-release /etc/redhat-release | head -1)" -lt 7 ]; then
                _err_msg "$(_red "This installer requires version $OS_NAME 7 or higher.")" && end_message && exit 1
            fi
        ;;
        'almalinux' | 'rhel' | 'rocky')
            # 检查almalinux/rhel/rocky版本是否小于8
            if [ "$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/redhat-release /etc/rocky-release | head -1)" -lt 8 ]; then
                _err_msg "$(_red "This installer requires version $OS_NAME 8 or higher.")" && end_message && exit 1
            fi
        ;;
        *) _err_msg "$(_red 'The current operating system is not supported!')" && end_message && exit 1 ;;
    esac
}

function check_install {
    if _exists docker >/dev/null 2>&1 \
        || docker --version >/dev/null 2>&1 \
        || docker compose version >/dev/null 2>&1 \
        || _exists docker-compose >/dev/null 2>&1; then
        _err_msg "$(_red 'Docker is already installed. Exiting the installer.')" && end_message && exit 1
    fi
}

function clear_repos {
    [ -f "/etc/yum.repos.d/docker-ce.repo" ] &&  rm -f /etc/yum.repos.d/docker-ce.repo 2>/dev/null
    [ -f "/etc/yum.repos.d/docker-ce-staging.repo" ] &&  rm -f /etc/yum.repos.d/docker-ce-staging.repo 2>/dev/null
    [ -f "/etc/apt/keyrings/docker.asc" ] &&  rm -f /etc/apt/keyrings/docker.asc 2>/dev/null
    [ -f "/etc/apt/sources.list.d/docker.list" ] &&  rm -f /etc/apt/sources.list.d/docker.list 2>/dev/null
}

function fix_dpkg {
    pkill -9 -f 'apt|dpkg' 2>/dev/null
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock 2>/dev/null
    dpkg --configure -a
}

function docker_install {
    local VERSION_CODE REPO_URL GPGKEY_URL

    _info_msg "$(_yellow 'Installing the Docker environment!')"
    printf '\n'
    if [ "$OS_NAME" = "almalinux" ] || [ "$OS_NAME" = "centos" ] || [ "$OS_NAME" = "rocky" ]; then
        pkg_uninstall docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine >/dev/null 2>&1

        if [ "$COUNTRY" = "CN" ]; then
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
        if [ "$COUNTRY" = "CN" ]; then
            dnf config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/rhel/docker-ce.repo
        else
            dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
        fi
        dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    elif [ "$OS_NAME" = "debian" ] || [ "$OS_NAME" = "ubuntu" ]; then
        VERSION_CODE="$(grep "^VERSION_CODENAME" /etc/os-release | cut -d= -f2)"
        pkg_uninstall docker.io docker-doc docker-compose podman-docker containerd runc >/dev/null 2>&1

        if [ "$COUNTRY" = "CN" ]; then
            REPO_URL="https://mirrors.aliyun.com/docker-ce/linux/${OS_NAME}"
            GPGKEY_URL="https://mirrors.aliyun.com/docker-ce/linux/${OS_NAME}/gpg"
        else
            REPO_URL="https://download.docker.com/linux/${OS_NAME}"
            GPGKEY_URL="https://download.docker.com/linux/${OS_NAME}/gpg"
        fi

        fix_dpkg
        apt-get -qq update
        apt-get install -y -qq ca-certificates curl
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL "$GPGKEY_URL" -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc

        # add the repository to apt sources
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] $REPO_URL $VERSION_CODE stable" |  tee /etc/apt/sources.list.d/docker.list >/dev/null
        apt-get -qq update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    else
        _err_msg "$(_red 'The current operating system is not supported!')" && end_message && exit 1
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
        _err_msg "$(_red 'Docker status check failed or service not starting. Check logs or start Docker manually.')" && end_message && exit 1
    fi
}

function docker_version {
    local DOCKER_V=""
    local DOCKER_COMPOSE_V=""

    # 获取Docker版本
    if _exists docker >/dev/null 2>&1; then
        DOCKER_V=$(docker --version | awk -F '[ ,]' '{print $3}')
    elif _exists docker.io >/dev/null 2>&1; then
        DOCKER_V=$(docker.io --version | awk -F '[ ,]' '{print $3}')
    fi

    # 获取Docker Compose版本
    if docker compose version >/dev/null 2>&1; then
        DOCKER_COMPOSE_V=$(docker compose version --short)
    elif _exists docker-compose >/dev/null 2>&1; then
        DOCKER_COMPOSE_V=$(docker-compose version --short)
    fi

    echo
    echo "Docker Version: v$DOCKER_V"
    echo "Docker Compose Version: v$DOCKER_COMPOSE_V"
    echo
    _yellow "Get Docker information"
    sleep 2
    docker version 2>/dev/null
    echo
    echo "================================================================================"
    echo
    echo "To run the Docker daemon as a fully privileged service, but granting non-root"
    echo "users access, refer to https://docs.docker.com/go/daemon-access/"
    echo
    echo "WARNING: Access to the remote API on a privileged Docker daemon is equivalent"
    echo "         to root access on the host. Refer to the 'Docker daemon attack surface'"
    echo "         documentation for details: https://docs.docker.com/go/attack-surface/"
    echo
    echo "================================================================================"
    echo
}

function get_docker {
    clear_screen
    show_logo
    pre_check
    os_permission
    check_install
    clear_repos
    docker_install
    check_status
    docker_version
    end_message
}

get_docker