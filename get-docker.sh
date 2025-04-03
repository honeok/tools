#!/usr/bin/env bash
# vim:sw=4:ts=4:et
#
# Description: This script installs the latest version of Docker Community Edition (CE) on supported Linux distributions.
#
# Copyright (c) 2023-2025 honeok <honeok@duck.com>
#
# References:
# https://docs.docker.com/engine/install
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

# 当前脚本版本号
readonly version='v0.1.5 (2025.04.03)'

red='\033[91m'
green='\033[92m'
yellow='\033[93m'
purple='\033[95m'
cyan='\033[96m'
white='\033[0m'
function _red { echo -e "${red}$*${white}"; }
function _green { echo -e "${green}$*${white}"; }
function _yellow { echo -e "${yellow}$*${white}"; }
function _purple { echo -e "${purple}$*${white}"; }
function _cyan { echo -e "${cyan}$*${white}"; }

function _err_msg { echo -e "\033[41m\033[1mError${white} $*"; }
function _suc_msg { echo -e "\033[42m\033[1mSuccess${white} $*"; }
function _info_msg { echo -e "\033[43m\033[1mTis${white} $*"; }

# 环境变量用于在debian或ubuntu操作系统中设置非交互式 (noninteractive) 安装模式
export DEBIAN_FRONTEND=noninteractive

# 各变量默认值
getdocker_pid='/tmp/getdocker.pid'
os_info=$(grep "^PRETTY_NAME=" /etc/os-release | cut -d '"' -f 2 | sed 's/ (.*)//')
os_name=$(grep "^ID=" /etc/os-release | awk -F'=' '{print $2}' | sed 's/"//g')
ua_browser='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'

if [ -f "$getdocker_pid" ] && kill -0 "$(cat "$getdocker_pid")" 2>/dev/null; then
    _err_msg "$(_red 'The script seems to be running, please do not run it again!')" && exit 1
fi

function _exit {
    local return_value="$?"

    [ -f "$getdocker_pid" ] && rm -f "$getdocker_pid" 2>/dev/null
    exit "$return_value"
}

trap '_exit' SIGINT SIGQUIT SIGTERM EXIT

echo $$ > "$getdocker_pid"

# Logo generation from: https://www.lddgo.net/string/text-to-ascii-art (Small Slant)
function show_logo {
    echo -e "$yellow  _____    __     __        __ 
 / ______ / /____/ ___ ____/ /_____ ____
/ (_ / -_/ __/ _  / _ / __/  '_/ -_/ __/
\___/\__/\__/\_,_/\___\__/_/\_\\__/_/
"
    _green "System   : $os_info"
    echo "$(_yellow "Version  : $version") $(_purple '\xF0\x9F\x90\xB3')"
    _cyan 'bash <(curl -sL https://github.com/honeok/Tools/raw/master/get-docker.sh)'
    printf "\n"
}

# 清屏函数
function clear_screen {
    if [ -t 1 ]; then
        tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
    fi
}

function _exists {
    local _cmd="$1"
    if type "$_cmd" >/dev/null 2>&1; then
        return 0
    elif command -v "$_cmd" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

function runtime_count {
    local runcount
    runcount=$(curl -fskL -m 10 --retry 1 "https://hits.honeok.com/get-docker?action=hit")
    today=$(echo "$runcount" | grep '"daily"' | sed 's/.*"daily": *\([0-9]*\).*/\1/')
    total=$(echo "$runcount" | grep '"total"' | sed 's/.*"total": *\([0-9]*\).*/\1/')
}

function end_message {
    local current_time
    current_time=$(date '+%Y-%m-%d %H:%M:%S %Z')

    runtime_count
    _green "Current server time: $current_time Script completed."
    _purple "Thanks for using! More info: https://www.honeok.com"
    if [ -n "$today" ] && [ -n "$total" ]; then
        echo "$(_yellow 'Number of script runs today:') $(_cyan "$today") $(_yellow 'total number of script runs:') $(_cyan "$total")"
    fi
}

function pre_check {
    # 备用 www.prologis.cn
    # 备用 www.autodesk.com.cn
    # 备用 www.keysight.com.cn
    cloudflare_api='www.qualcomm.cn'

    if [ "$(id -ru)" -ne 0 ] || [ "$EUID" -ne 0 ]; then
        _err_msg "$(_red 'This script must be run as root!')" && exit 1
    fi
    if [ "$(ps -p $$ -o comm=)" != "bash" ] || readlink /proc/$$/exe | grep -q "dash"; then
        _err_msg "$(_red 'This script needs to be run with bash, not sh!')" && exit 1
    fi
    _loc=$(curl -A "$ua_browser" -fskL -m 3 "https://$cloudflare_api/cdn-cgi/trace" | grep -i '^loc=' | cut -d'=' -f2 | xargs)
    if [ -z "$_loc" ]; then
        _err_msg "$(_red 'Cannot retrieve server location. Check your network and try again.')" && end_message && exit 1
    fi
}

function os_permission {
    case "$os_name" in
        'debian')
            # 检查debian版本是否小于10
            if [ "$(grep -oE '[0-9]+' /etc/debian_version | head -1)" -lt 10 ]; then
                _err_msg "$(_red 'This version of Debian is no longer supported!')" && end_message && exit 1
            fi
        ;;
        'ubuntu')
            # 检查ubuntu版本是否小于20.04
            if [ "$(grep "^VERSION_ID" /etc/*-release | cut -d '"' -f 2 | tr -d '.')" -lt '2004' ]; then
                _err_msg "$(_red 'This version of Ubuntu is no longer supported!')" && end_message && exit 1
            fi
        ;;
        'centos')
            if [ "$(grep -shoE '[0-9]+' /etc/centos-release /etc/redhat-release | head -1)" -lt 7 ]; then
                _err_msg "$(_red "This installer requires version $os_name 7 or higher.")" && end_message && exit 1
            fi
        ;;
        'almalinux' | 'rhel' | 'rocky')
            # 检查almaLinux/rhel/rocky版本是否小于8
            if [ "$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/redhat-release /etc/rocky-release | head -1)" -lt 8 ]; then
                _err_msg "$(_red "This installer requires version $os_name 8 or higher.")" && end_message && exit 1
            fi
        ;;
        *)
            _err_msg "$(_red 'The current operating system is not supported!')" && end_message && exit 1
        ;;
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
    local version_code repo_url gpgkey_url

    _info_msg "$(_yellow 'Installing the Docker environment!')"
    if [ "$os_name" = "almalinux" ] || [ "$os_name" = "centos" ] || [ "$os_name" = "rocky" ]; then
        pkg_uninstall docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine >/dev/null 2>&1

        if [ "$_loc" = "CN" ]; then
            repo_url="https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo"
        else
            repo_url="https://download.docker.com/linux/centos/docker-ce.repo"
        fi

        if _exists dnf >/dev/null 2>&1; then
            dnf config-manager --help >/dev/null 2>&1 || dnf install -y dnf-plugins-core
            dnf config-manager --add-repo "$repo_url" 2>/dev/null
            dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        elif _exists yum >/dev/null 2>&1; then
            rpm -q yum-utils >/dev/null 2>&1 || yum install -y yum-utils
            yum-config-manager --add-repo "$repo_url" >/dev/null 2>&1
            yum makecache fast
            yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        fi
    elif [ "$os_name" = "rhel" ]; then
        pkg_uninstall docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine podman runc >/dev/null 2>&1

        dnf config-manager --help >/dev/null 2>&1 || dnf install -y dnf-plugins-core
        if [ "$_loc" = "CN" ]; then
            dnf config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/rhel/docker-ce.repo
        else
            dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
        fi
        dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    elif [ "$os_name" = "debian" ] || [ "$os_name" = "ubuntu" ]; then
        version_code="$(grep "^VERSION_CODENAME" /etc/*-release | cut -d= -f2)"
        pkg_uninstall docker.io docker-doc docker-compose podman-docker containerd runc >/dev/null 2>&1

        if [ "$_loc" = "CN" ]; then
            repo_url="https://mirrors.aliyun.com/docker-ce/linux/${os_name}"
            gpgkey_url="https://mirrors.aliyun.com/docker-ce/linux/${os_name}/gpg"
        else
            repo_url="https://download.docker.com/linux/${os_name}"
            gpgkey_url="https://download.docker.com/linux/${os_name}/gpg"
        fi

        fix_dpkg
        apt-get -qq update
        apt-get install -y -qq ca-certificates curl
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL "$gpgkey_url" -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc

        # add the repository to apt sources
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] $repo_url $version_code stable" |  tee /etc/apt/sources.list.d/docker.list >/dev/null
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
    local docker_v=""
    local docker_compose_v=""

    # 获取Docker版本
    if _exists docker >/dev/null 2>&1; then
        docker_v=$(docker --version | awk -F '[ ,]' '{print $3}')
    elif _exists docker.io >/dev/null 2>&1; then
        docker_v=$(docker.io --version | awk -F '[ ,]' '{print $3}')
    fi

    # 获取Docker Compose版本
    if docker compose version >/dev/null 2>&1; then
        docker_compose_v=$(docker compose version --short)
    elif _exists docker-compose >/dev/null 2>&1; then
        docker_compose_v=$(docker-compose version --short)
    fi

    echo
    echo "Docker Version: v$docker_v"
    echo "Docker Compose Version: v$docker_compose_v"
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