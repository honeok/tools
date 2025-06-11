#!/usr/bin/env bash
#
# Description: This script is used to automatically install the latest Linux kernel version.
#
# Copyright (c) 2025 honeok <honeok@disroot.org>
#
# References:
# https://github.com/teddysun/across
# https://gitlab.com/fscarmen/warp
# https://github.com/kejilion/sh
#
# SPDX-License-Identifier: Apache-2.0

# 当前脚本版本号
readonly VERSION='v1.0.4 (2025.06.11)'

# https://www.graalvm.org/latest/reference-manual/ruby/UTF8Locale
if locale -a 2>/dev/null | grep -qiE -m 1 "UTF-8|utf8"; then
    export LANG=en_US.UTF-8
fi
# 环境变量用于在debian或ubuntu操作系统中设置非交互式 (noninteractive) 安装模式
export DEBIAN_FRONTEND=noninteractive
# 设置PATH环境变量
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

# 自定义彩色字体
_red() { printf "\033[91m%b\033[0m\n" "$*"; }
_green() { printf "\033[92m%b\033[0m\n" "$*"; }
_yellow() { printf "\033[93m%b\033[0m\n" "$*"; }
_blue() { printf "\033[94m%b\033[0m\n" "$*"; }
_cyan() { printf "\033[96m%b\033[0m\n" "$*"; }
_err_msg() { printf "\033[41m\033[1mError\033[0m %b\n" "$*"; }
_suc_msg() { printf "\033[42m\033[1mSuccess\033[0m %b\n" "$*"; }
_info_msg() { printf "\033[43m\033[1mInfo\033[0m %b\n" "$*"; }

# 各变量默认值
RANDOM_CHAR="$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 5)"
TEMP_DIR="/tmp/kernel_$RANDOM_CHAR"
UA_BROWSER='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'

# curl默认参数
declare -a CURL_OPTS=(--max-time 5 --retry 1 --retry-max-time 10)

_exit() {
    local RET_CODE="$?"
    rm -rf "$TEMP_DIR" >/dev/null 2>&1
    [ -f /etc/apt/sources.list.d/xanmod-release.list ] && rm -f /etc/apt/sources.list.d/xanmod-release.list
    exit "$RET_CODE"
}

trap '_exit' SIGINT SIGQUIT SIGTERM EXIT

mkdir -p "$TEMP_DIR" >/dev/null 2>&1

# 分割符
separator() { printf "%-25s\n" "-" | sed 's/\s/-/g'; }

reading() {
    local PROMPT
    PROMPT="$1"
    read -rep "$(_yellow "$PROMPT")" "$2"
}

# 安全清屏函数
clrscr() {
    ( [ -t 1 ] && tput clear 2>/dev/null ) || echo -e "\033[2J\033[H" || clear
}

# 打印错误信息并退出
die() {
    _err_msg "$(_red "$@")" >&2; exit 1
}

_exists() {
    local _CMD="$1"
    if type "$_CMD" >/dev/null 2>&1; then return 0
    elif command -v "$_CMD" >/dev/null 2>&1; then return 0
    elif which "$_CMD" >/dev/null 2>&1; then return 0
    else return 1
    fi
}

_is_64bit() {
    if [ "$(getconf WORD_BIT)" = '32' ] && [ "$(getconf LONG_BIT)" = '64' ]; then return 0
    else return 1
    fi
}

pkg_install() {
    for pkg in "$@"; do
        if _exists apt-get; then
            apt-get update
            apt-get install -y -q "$pkg"
        else
            die "The package manager is not supported."
        fi
    done
}

pkg_uninstall() {
    for pkg in "$@"; do
        if _exists apt-get; then
            apt-get purge -y "$pkg"
        else
            die "The package manager is not supported."
        fi
    done
}

pre_check() {
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
    if [ -z "$BASH_VERSION" ]; then
        die "This script needs to be run with bash, not sh!"
    fi
    if [ "$(cd -P -- "$(dirname -- "$0")" && pwd -P)" != "$TEMP_DIR" ]; then
        cd "$TEMP_DIR" 2>/dev/null || die "Can't access temporary working directory. Check permissions and try again."
    fi
    if ! _is_64bit; then
        die "Not a 64-bit system, not supported."
    fi
}

cdn_check() {
    # 备用 www.prologis.cn www.autodesk.com.cn www.keysight.com.cn
    COUNTRY="$(curl --user-agent "$UA_BROWSER" -fsL "${CURL_OPTS[@]}" "http://www.qualcomm.cn/cdn-cgi/trace" | grep -i '^loc=' | cut -d'=' -f2 | grep .)"
    if [ "$COUNTRY" != "CN" ]; then
        GITHUB_PROXY=""
    elif [ "$COUNTRY" = "CN" ]; then
        curl -sL --retry 2 --connect-timeout 5 -w "%{http_code}" "https://files.m.daocloud.io/github.com/honeok/honeok/raw/master/README.md" -o /dev/null 2>/dev/null | grep -q "^200$" && GITHUB_PROXY='https://files.m.daocloud.io/' || GITHUB_PROXY='https://gh-proxy.com/'
    else
        GITHUB_PROXY='https://gh-proxy.com/'
    fi
}

os_reboot() {
    local CHOICE
    _yellow "The system needs to reboot."
    reading "Do you want to restart system? (y/n): " CHOICE
    case "$CHOICE" in
        [Yy] | "" ) ( _exists reboot && reboot ) || shutdown -r now ;;
        * ) _yellow "Reboot has been canceled"; exit 0 ;;
    esac
    exit 0
}

os_full() {
    local -a RELEASE_REGEX RELEASE_DISTROS
    RELEASE_REGEX=("almalinux" "centos" "debian" "fedora" "red hat|rhel" "rocky" "ubuntu")
    RELEASE_DISTROS=("almalinux" "centos" "debian" "fedora" "rhel" "rocky" "ubuntu")

    if [ -s /etc/os-release ]; then
        OS_INFO="$(grep -i '^PRETTY_NAME=' /etc/os-release | awk -F'=' '{print $NF}' | sed 's#"##g')"
    elif [ -x "$(type -p hostnamectl)" ]; then
        OS_INFO="$(hostnamectl | grep -i system | cut -d: -f2 | xargs)"
    elif [ -x "$(type -p lsb_release)" ]; then
        OS_INFO="$(lsb_release -sd 2>/dev/null)"
    elif [ -s /etc/lsb-release ]; then
        OS_INFO="$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)"
    elif [ -s /etc/redhat-release ]; then
        OS_INFO="$(grep . /etc/redhat-release)"
    elif [ -s /etc/issue ]; then
        # shellcheck disable=SC1003
        OS_INFO="$(grep . /etc/issue | cut -d '\' -f1 | sed '/^[ ]*$/d')"
    fi
    for release in "${!RELEASE_REGEX[@]}"; do
        [[ "${OS_INFO,,}" =~ ${RELEASE_REGEX[release]} ]] && OS_NAME="${RELEASE_DISTROS[release]}" && break
    done
    [ -z "$OS_NAME" ] && die "This Linux distribution is not supported."
}

os_version() {
    local MAIN_VER
    MAIN_VER="$(printf "%s" "$OS_INFO" | grep -oE "[0-9.]+")"
    MAJOR_VER="${MAIN_VER%%.*}"
}

show_logo() {
    _yellow "\
   __                           __  \xF0\x9F\x92\x80
  / /__ ___   ____  ___  ___   / /
 /  '_// -_) / __/ / _ \/ -_) / / 
/_/\_\ \__/ /_/   /_//_/\__/ /_/  
                                  "
    _green "System   : $OS_INFO"
    echo "$(_yellow "Version  : $VERSION") $(_cyan "\xF0\x9F\xAA\x90")"
    _blue 'bash <(curl -sL https://github.com/honeok/Tools/raw/master/kernel.sh)'
    echo
}

kernel_version() {
    if _exists uname; then KERNEL_VERSION="$(uname -r)"
    elif _exists hostnamectl; then KERNEL_VERSION="$(hostnamectl | sed -n 's/^.*Kernel: Linux //p')"
    else die "Command not found."
    fi
}

os_check() {
    local VIRT MIN_VER
    local -a UNSUPPORTED=("docker" "lxc" "openvz")
    if _exists virt-what; then VIRT="$(virt-what 2>/dev/null)"
    elif _exists systemd-detect-virt; then VIRT="$(systemd-detect-virt 2>/dev/null)"
    elif _exists hostnamectl; then VIRT="$(hostnamectl | awk '/Virtualization:/{print $NF}')"
    else die "No virtualization detection tool found."
    fi
    for type in "${UNSUPPORTED[@]}"; do
        if [[ "${VIRT,,}" =~ $type ]] || [[ -d "/proc/vz" ]]; then
            die "Virtualization method is $type which is not supported."
        fi
    done
    case "$OS_NAME" in
        almalinux | centos | fedora | rhel | rocky ) MIN_VER=7 ;;
        debian ) MIN_VER=8 ;;
        ubuntu ) MIN_VER=16 ;;
        *) die "Not supported OS." ;;
    esac
    if [[ -n "$MAJOR_VER" && "$MAJOR_VER" -lt "$MIN_VER" ]]; then
        die "Unsupported $OS_NAME version: $MAJOR_VER. Please upgrade to $OS_NAME $MIN_VER or newer."
    fi
}

add_swap() {
    local NEW_SWAP="$1"
    local FSTYPE
    FSTYPE="$(df --output=fstype / | tail -1)"

    if _exists fallocate && [ "$FSTYPE" != "btrfs" ]; then fallocate -l "${NEW_SWAP}M" /swapfile
    elif _exists dd; then dd if=/dev/zero of=/swapfile bs=1M count="$NEW_SWAP" status=none
    else die "No fallocate or dd Command"
    fi
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    grep -qF '/swapfile' /etc/fstab || echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
    _suc_msg "$(_green "Swap added: $NEW_SWAP MB")"
}

swap_check() {
    local MEM_TOTAL SWAP_TOTAL
    MEM_TOTAL="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
    SWAP_TOTAL="$(awk '/SwapTotal/ {print $2}' /proc/meminfo)"
    (( MEM_TOTAL /= 1024, SWAP_TOTAL /= 1024 ))
    (( MEM_TOTAL <= 900 && SWAP_TOTAL == 0 )) && add_swap 1024
}

on_bbr() {
    if grep -qi '^net.core.default_qdisc' /etc/sysctl.conf; then
        grep -qi '^net.core.default_qdisc *= *fq' /etc/sysctl.conf || sed -i 's/^net.core.default_qdisc.*/net.core.default_qdisc = fq/' /etc/sysctl.conf
    else
        echo 'net.core.default_qdisc = fq' >> /etc/sysctl.conf
    fi
    if grep -qi '^net.ipv4.tcp_congestion_control' /etc/sysctl.conf; then
        grep -qi '^net.ipv4.tcp_congestion_control *= *bbr' /etc/sysctl.conf || sed -i 's/^net.ipv4.tcp_congestion_control.*/net.ipv4.tcp_congestion_control = bbr/' /etc/sysctl.conf
    else
        echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
    fi
    if [ "$(sysctl -n net.core.default_qdisc 2>/dev/null)" != "fq" ] || [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" != "bbr" ]; then
        sysctl -p >/dev/null 2>&1 && _suc_msg "$(_green "BBR enabled.")"
    fi
}

rhel_mirror() {
    local -a MIRRORS=(
        mirrors.aliyun.com
        mirrors.huaweicloud.com
        mirror.nju.edu.cn
        mirrors.tuna.tsinghua.edu.cn
    )

    {
        for MIRROR in "${MIRRORS[@]}"; do
            {
                AVG="$(ping -c3 -q "$MIRROR" | awk -F'/' '/rtt/ {printf "%.0f", $5}')"
                [ -n "$AVG" ] && echo "$AVG $MIRROR"
            } 2>/dev/null &
        done
        wait
    } | sort -n | head -n1 | awk '{print $2}'
}

# http://developer.aliyun.com/mirror/elrepo?spm=a2c6h.13651102.0.0.b9361b11Q0alNh
# https://www.rockylinux.cn/notes/rocky-linux-9-nei-he-sheng-ji-zhi-6.html
rhel_install() {
    local ELREPO_URL LATEST_VERSION RPM_NAME BEST_MIRROR

    case "$MAJOR_VER" in
        7 )
            [[ ! "$(uname -m 2>/dev/null)" =~ ^(x86_64|amd64)$ ]] && die "Current architecture: $(uname -m) is not supported."
            ELREPO_URL="http://mirrors.coreix.net/elrepo-archive-archive/kernel/el7/x86_64/RPMS"
            LATEST_VERSION="$(curl -fskL --retry 2 "$ELREPO_URL" | grep -oP 'kernel-ml(-devel)?-\K[0-9][^"]+(?=\.el7\.elrepo\.x86_64\.rpm)' | sort -V | uniq -d | tail -n1)"
            for suffix in "" "-devel"; do
                RPM_NAME="kernel-ml$suffix-$LATEST_VERSION.el7.elrepo.x86_64.rpm"
                curl -fLO "$ELREPO_URL/$RPM_NAME"
            done
            yum localinstall -y kernel-ml*
            # 更改内核启动顺序
            grub2-set-default 0 && grub2-mkconfig -o /etc/grub2.cfg
            grubby --args="user_namespace.enable=1" --update-kernel="$(grubby --default-kernel)"
            rm -f kernel-ml*
        ;;
        8 | 9 )
            dnf -y install epel-release
            rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org # 导入ELRepo GPG公钥
            ( rpm -q elrepo-release >/dev/null 2>&1 && [ ! -f /etc/yum.repos.d/elrepo.repo ] \
                && dnf -y reinstall "https://www.elrepo.org/elrepo-release-$MAJOR_VER.el$MAJOR_VER.elrepo.noarch.rpm" ) \
                || dnf -y install "https://www.elrepo.org/elrepo-release-$MAJOR_VER.el$MAJOR_VER.elrepo.noarch.rpm"
            if [[ "$COUNTRY" = "CN" && -f /etc/yum.repos.d/elrepo.repo ]]; then
                BEST_MIRROR="$(rhel_mirror)"
                sed -i 's/mirrorlist=/#mirrorlist=/g' /etc/yum.repos.d/elrepo.repo
                sed -i "s#elrepo.org/linux#$BEST_MIRROR/elrepo#g" /etc/yum.repos.d/elrepo.repo
            fi
            dnf -y install --nogpgcheck --enablerepo=elrepo-kernel kernel-ml kernel-ml-devel
        ;;
        * )
            die "Unsupported system version."
        ;;
    esac
    on_bbr
    os_reboot
}

# 红帽系发行版交互菜单
rhel_menu() {
    local CHOICE KERNELS
    if echo "$KERNEL_VERSION" | grep -qi 'elrepo'; then
        _green "ELRepo kernel detected."
        echo "Current kernel: $KERNEL_VERSION"
        echo
        _yellow "Kernel Management"
        separator
        echo "1. Update ELRepo kernel"
        echo "2. Uninstall ELRepo kernel"
        separator
        reading "Enter your choice: " CHOICE
        KERNELS="$(rpm -qa | while read -r pkg; do [[ $pkg == *kernel* && $pkg == *elrepo* ]] && echo "$pkg"; done;)"
        case "$CHOICE" in
            1 ) ( [ -n "$KERNELS" ] && rpm -ev --nodeps "$KERNELS" ); rhel_install ;;
            2 ) ( [ -n "$KERNELS" ] && rpm -ev --nodeps "$KERNELS" )
                _suc_msg "$(_green "ELRepo kernel uninstalled. Takes effect after reboot.")"; os_reboot ;;
            * ) die "Invalid selection." ;;
        esac
    else
        separator
        _red "Please back up your data. Linux kernel will be upgraded."
        echo "Kernel upgrade may improve performance and security. Recommended for testing, use caution in production."
        separator
        reading "Proceed with upgrade? (y/n): " CHOICE
        case "$CHOICE" in
            [Yy] | "" ) rhel_install ;;
            [Nn] ) _yellow "Cancelled by user."; exit 0 ;;
            * ) die "Invalid selection" ;;
        esac
    fi
}

debian_xanmod_install() {
    local XANMOD_VERSION

    pkg_install gnupg
    curl -fsL "${GITHUB_PROXY}github.com/kejilion/sh/raw/main/archive.key" | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
    # 添加存储库
    echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
    XANMOD_VERSION="$(curl -fsL "${GITHUB_PROXY}github.com/kejilion/sh/raw/main/check_x86-64_psabi.sh" | awk -f - | awk -F 'x86-64-v' '{print $2+0}')"
    pkg_install "linux-xanmod-x64v$XANMOD_VERSION"
    on_bbr
    os_reboot
}

debian_xanmod_menu() {
    local CHOICE

    if dpkg -l | grep -q 'linux-xanmod'; then
        _green "XanMod BBRv3 kernel detected."
        echo "Current kernel: $KERNEL_VERSION"
        separator
        echo "1. Update BBRv3 kernel"
        echo "2. Uninstall BBRv3 kernel"
        separator
        reading "Enter your choice: " CHOICE
        case "$CHOICE" in
            1 | "" ) pkg_uninstall 'linux-*xanmod1*'; update-grub; debian_xanmod_install ;;
            2 ) pkg_uninstall 'linux-*xanmod1*'; update-grub; os_reboot ;;
            * ) die "Invalid selection" ;;
        esac
    else
        _red "Please back up your data. XanMod BBR3 kernel will be upgraded."
        echo "Only supports Debian/Ubuntu and only supports x86_64 architecture."
        separator
        reading "Proceed with upgrade? (y/n): " CHOICE
        case "$CHOICE" in
            [Yy] | "" ) debian_xanmod_install ;;
            [Nn] ) _yellow "Cancelled by user."; exit 0 ;;
            * ) die "Invalid selection" ;;
        esac
    fi
}

before_run() {
    clrscr
    pre_check
    cdn_check
    os_full
    os_version
    show_logo
    kernel_version
    os_check
    swap_check
}

kernel() {
    before_run
    [[ "$OS_NAME" =~ ^(almalinux|centos|fedora|rhel|rocky)$ ]] && rhel_menu
    [[ "$OS_NAME" =~ ^(debian|ubuntu)$ ]] && debian_xanmod_menu
}

kernel