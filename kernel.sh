#!/usr/bin/env bash
#
# Description: This script is used to automatically install the latest linux kernel version.
#
# Copyright (c) 2025 honeok <honeok@disroot.org>
#
# References:
# https://github.com/teddysun/across
# https://gitlab.com/fscarmen/warp
# https://github.com/kejilion/sh
# https://github.com/bin456789/reinstall
#
# SPDX-License-Identifier: Apache-2.0

# 当前脚本版本号
readonly VERSION='v1.1.1 (2025.06.13)'
# shellcheck disable=SC2034
readonly SCRIPT_ID='ae52ef86-b2c0-486a-a9e7-b23b5d6fc50d'

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
declare -a CURL_OPTS=(--max-time 5 --retry 2 --retry-max-time 10)

# 分割符
separator() { printf "%-25s\n" "-" | sed 's/\s/-/g'; }

# 安全清屏函数
clrscr() {
    ([ -t 1 ] && tput clear 2>/dev/null) || echo -e "\033[2J\033[H" || clear
}

# 打印错误信息并退出
die() {
    _err_msg >&2 "$(_red "$@")"; exit 1
}

# 检测系统UTF-8语言环境
UTF8_LOCALE=$(locale -a 2>/dev/null | grep -iE -m 1 "UTF-8|utf8")
if [ -z "$UTF8_LOCALE" ]; then
    die "No UTF-8 locale found."
else
    export LC_ALL="$UTF8_LOCALE"
    export LANG="$UTF8_LOCALE"
    export LANGUAGE="$UTF8_LOCALE"
fi

# 终止信号捕获退出前清理操作
_exit() {
    local ERR_CODE="$?"
    rm -rf "$TEMP_DIR" >/dev/null 2>&1
    [ -f /etc/apt/sources.list.d/xanmod-release.list ] && rm -f /etc/apt/sources.list.d/xanmod-release.list
    exit "$ERR_CODE"
}

# 终止信号捕获
trap '_exit' SIGINT SIGQUIT SIGTERM EXIT

# 临时工作目录
mkdir -p "$TEMP_DIR" >/dev/null 2>&1
if [ "$(cd -P -- "$(dirname -- "$0")" && pwd -P)" != "$TEMP_DIR" ]; then
    cd "$TEMP_DIR" >/dev/null 2>&1 || die "Can't access temporary working directory."
fi

reading() {
    local PROMPT
    PROMPT="$1"
    read -rep "$(_yellow "$PROMPT")" "$2"
}

# 用于判断命令是否存在
_exists() {
    local _CMD="$1"
    if type "$_CMD" >/dev/null 2>&1; then return 0
    elif command -v "$_CMD" >/dev/null 2>&1; then return 0
    elif which "$_CMD" >/dev/null 2>&1; then return 0
    else return 1
    fi
}

# 用于判断当前系统是否为64位系统
_is_64bit() {
    if _exists getconf; then [[ "$(getconf WORD_BIT)" = 32 && "$(getconf LONG_BIT)" = 64 ]] && return 0
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

# 运行前校验, 确保root用户运行和bash环境, 仅支持固定64位系统
pre_check() {
    if [ "$EUID" -ne 0 ] || [ "$(id -ru)" -ne 0 ]; then
        die "This script must be run as root!"
    fi
    if [ -z "$BASH_VERSION" ]; then
        die "This script needs to be run with bash, not sh!"
    fi
    if ! _is_64bit; then
        die "Not a 64-bit system, not supported."
    fi
}

# 设置github代理, 海外服务器仅ipv4通过将代理设置为空
# COUNTRY 和 GITHUB_PROXY 变量设置全局生效
cdn_check() {
    # 备用 www.prologis.cn www.autodesk.com.cn www.keysight.com.cn
    COUNTRY="$(curl --user-agent "$UA_BROWSER" -sL -4 "${CURL_OPTS[@]}" "http://www.qualcomm.cn/cdn-cgi/trace" | grep -i '^loc=' | cut -d'=' -f2 | grep .)"
    if [ "$COUNTRY" != "CN" ]; then
        GITHUB_PROXY=""
    elif [ "$COUNTRY" = "CN" ]; then
        (curl "${CURL_OPTS[@]}" --connect-timeout 5 -sL -w "%{http_code}" "https://files.m.daocloud.io/github.com/honeok/honeok/raw/master/README.md" -o /dev/null 2>/dev/null | grep -q "^200$" \
        && GITHUB_PROXY='https://files.m.daocloud.io/') \
        || GITHUB_PROXY='https://gh-proxy.com/'
    else
        GITHUB_PROXY='https://gh-proxy.com/'
    fi
}

os_reboot() {
    local CHOICE
    [ "$REBOOT" = 1 ] && { _exists reboot && reboot || (_exists shutdown && shutdown -r now) || die "restart command not found."; exit 0; }
    _yellow "The system needs to reboot."
    reading "Do you want to restart system? (y/n): " CHOICE
    case "$CHOICE" in
        [Yy] | "" ) { _exists reboot && reboot || (_exists shutdown && shutdown -r now) || die "restart command not found."; } ;;
        * ) _yellow "Reboot has been canceled"; exit 0 ;;
    esac
    exit 0
}

# 多方式判断操作系统
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
    [ -z "$OS_NAME" ] && die "This linux distribution is not supported."
}

# 提取主版本号 8 or 9
os_version() {
    local MAIN_VER
    MAIN_VER="$(grep -oE "[0-9.]+" <<< "$OS_INFO")"
    MAJOR_VER="${MAIN_VER%%.*}"
}

show_logo() {
    _yellow "\
   __                           __  \xF0\x9F\x90\xA7
  / /__ ___   ____  ___  ___   / /
 /  '_// -_) / __/ / _ \/ -_) / / 
/_/\_\ \__/ /_/   /_//_/\__/ /_/  
                                  "
    _green "System version  : $OS_INFO"
    echo "$(_yellow "Script version  : $VERSION") $(_cyan "\xF0\x9F\xAA\x90")"
    echo "$(_blue "Usage: ")" 'bash <(curl -sL https://github.com/honeok/Tools/raw/master/kernel.sh)'
    echo
}

show_usage() {
    local SCRIPT_NAME
    SCRIPT_NAME="$(basename "${0:-kernel.sh}")"

    cat <<EOF
Usage: bash $SCRIPT_NAME [OPTIONS] [BRANCH]

Available options:
        lt: Long-Term Support (LTS) branch
        ml: Mainline branch (latest stable)

        --almalinux    lt | ml
        --centos       lt | ml
        --fedora       lt | ml
        --rhel         lt | ml
        --rocky        lt | ml

        --debian
        --ubuntu

        --bbr          Enable BBR + FQ after upgrade
        --reboot       Reboot automatically after upgrade

Example:
        bash $SCRIPT_NAME --almalinux lt --bbr --reboot
EOF
    exit 1
}

kernel_version() {
    if _exists uname; then KERNEL_VERSION="$(uname -r)"
    elif _exists hostnamectl; then KERNEL_VERSION="$(hostnamectl | sed -n 's/^.*Kernel: Linux //p')"
    else die "Command not found."
    fi
}

# 虚拟化校验并校验支持的操作系统发行版最低版本
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
        debian ) MIN_VER=10 ;;
        ubuntu ) MIN_VER=18 ;;
        *) die "Not supported OS." ;;
    esac
    if [[ -n "$MAJOR_VER" && "$MAJOR_VER" -lt "$MIN_VER" ]]; then
        die "Unsupported $OS_NAME version: $MAJOR_VER. Please upgrade to $OS_NAME $MIN_VER or newer."
    fi
}

add_swap() {
    local NEW_SWAP="$1"
    local FSTYPE
    # 获取根分区 / 文件系统类型
    FSTYPE="$(df --output=fstype / | tail -1)"

    # btrfs是高级文件系统, 支持写时复制在这种机制下使用fallocate创建的文件实际上可能不是真正连续分配的块
    # swap 要求底层是物理连续分配的空间, 在btrfs上用fallocate创建swapfile, 启用swap时可能失败, 回退dd创建
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

# 校验交换内存, 有些云厂商可能只有 ≈ 850 MB 都认为需要增加 1024 MB虚拟内存
swap_check() {
    local MEM_TOTAL SWAP_TOTAL
    MEM_TOTAL="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
    SWAP_TOTAL="$(awk '/SwapTotal/ {print $2}' /proc/meminfo)"
    (( MEM_TOTAL /= 1024, SWAP_TOTAL /= 1024 ))
    (( MEM_TOTAL <= 850 && SWAP_TOTAL == 0 )) && add_swap 1024
}

# 开启bbr+fq
on_bbr() {
    if ! grep -qi '^net.core.default_qdisc.*fq' /etc/sysctl.conf; then
        grep -qi '^net.core.default_qdisc' /etc/sysctl.conf \
        && sed -i 's/^net.core.default_qdisc.*/net.core.default_qdisc = fq/' /etc/sysctl.conf \
        || echo 'net.core.default_qdisc = fq' >> /etc/sysctl.conf
    fi
    if ! grep -qi '^net.ipv4.tcp_congestion_control.*bbr' /etc/sysctl.conf; then
        grep -qi '^net.ipv4.tcp_congestion_control' /etc/sysctl.conf \
        && sed -i 's/^net.ipv4.tcp_congestion_control.*/net.ipv4.tcp_congestion_control = bbr/' /etc/sysctl.conf \
        || echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
    fi
    if [[ "$(sysctl -n net.core.default_qdisc 2>/dev/null)" != "fq" || "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" != "bbr" ]]; then
        sysctl -p >/dev/null 2>&1 && _suc_msg "$(_green "BBR enabled.")"
    fi
}

# 开启内核bbr+fq交互菜单
bbr_menu() {
    local CHOICE
    [ "$BBR" = 1 ] && on_bbr && return 0
    reading "Whether to use bbr + fq ? (y/n): " CHOICE
    case "$CHOICE" in
        [Yy] | "" ) on_bbr ;;
        [Nn] ) _yellow "Cancelled by user."; exit 0 ;;
        * ) die "Invalid selection" ;;
    esac
}

## 红帽系发行版相关
# 获取最低延迟的mirrors仓库, 用于替换红帽系发行版epel源
rhel_mirror() {
    local -a MIRRORS=(
        mirrors.aliyun.com
        mirrors.cloud.tencent.com
        mirrors.huaweicloud.com
        mirror.nju.edu.cn
        mirrors.ustc.edu.cn
        mirrors.tuna.tsinghua.edu.cn
    )

    {
        for MIRROR in "${MIRRORS[@]}"; do
            {
                ping -c3 -W 1 -q "$MIRROR" | awk -F'/' '/rtt/ {printf "%.0f %s\n", $5, "'"$MIRROR"'"}'
            } 2>/dev/null &
        done
        wait
    } | sort -n | awk 'NR==1 {print $2}'
}

# http://developer.aliyun.com/mirror/elrepo?spm=a2c6h.13651102.0.0.b9361b11Q0alNh
# https://www.rockylinux.cn/notes/rocky-linux-9-nei-he-sheng-ji-zhi-6.html
rhel_install() {
    local KERNEL_CHANNEL="$1"
    local ELREPO_URL LATEST_VERSION RPM_NAME BEST_MIRROR

    # 设置默认值为长期支持版本
    # 主线版本和长期支持版本
    KERNEL_CHANNEL="${KERNEL_CHANNEL:-lt}"
    case "$MAJOR_VER" in
        7 )
            [[ ! "$(uname -m 2>/dev/null)" =~ ^(x86_64|amd64)$ ]] && die "Current architecture: $(uname -m) is not supported."
            ELREPO_URL="https://mirrors.coreix.net/elrepo-archive-archive/kernel/el7/x86_64/RPMS"
            LATEST_VERSION="$(curl -skL --retry 2 "$ELREPO_URL" | grep -oP "kernel-$KERNEL_CHANNEL(-devel)?-\K[0-9][^\"<]+(?=\\.el7\\.elrepo\\.x86_64\\.rpm)" | sort -V | uniq -d | tail -n1)"
            for suffix in "" "-devel"; do
                RPM_NAME="kernel-$KERNEL_CHANNEL$suffix-$LATEST_VERSION.el7.elrepo.x86_64.rpm"
                curl --retry 2 -LO "$ELREPO_URL/$RPM_NAME"
            done
            yum localinstall -y "kernel-$KERNEL_CHANNEL"*
            # 更改内核启动顺序
            grub2-set-default 0 && grub2-mkconfig -o /etc/grub2.cfg
            grubby --args="user_namespace.enable=1" --update-kernel="$(grubby --default-kernel)"
            rm -f "kernel-$KERNEL_CHANNEL"*
        ;;
        8 | 9 | 10 )
            dnf -y install epel-release
            rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org # 导入ELRepo GPG公钥
            # 考虑elrepo-release可能安装, 但是repo文件被移除, 尝试重装repo文件
            (rpm -q elrepo-release >/dev/null 2>&1 && [ ! -f /etc/yum.repos.d/elrepo.repo ] \
                && dnf -y reinstall "https://www.elrepo.org/elrepo-release-$MAJOR_VER.el$MAJOR_VER.elrepo.noarch.rpm") \
                || dnf -y install "https://www.elrepo.org/elrepo-release-$MAJOR_VER.el$MAJOR_VER.elrepo.noarch.rpm"
            dnf makecache
            if [[ "$COUNTRY" = "CN" && -f /etc/yum.repos.d/elrepo.repo ]]; then
                # CN服务器取一个延迟最低的mirror地址替换
                BEST_MIRROR="$(rhel_mirror)"
                sed -i 's/mirrorlist=/#mirrorlist=/g' /etc/yum.repos.d/elrepo.repo
                sed -i "s#elrepo.org/linux#$BEST_MIRROR/elrepo#g" /etc/yum.repos.d/elrepo.repo
            fi
            dnf -y install --nogpgcheck --enablerepo=elrepo-kernel "kernel-$KERNEL_CHANNEL" "kernel-$KERNEL_CHANNEL-devel"
        ;;
        * )
            die "Unsupported system version."
        ;;
    esac
    bbr_menu
    os_reboot
}

# 红帽系发行版内核安装交互菜单
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
            1 ) ([ -n "$KERNELS" ] && rpm -ev --nodeps "$KERNELS"); rhel_install ;;
            2 ) ([ -n "$KERNELS" ] && rpm -ev --nodeps "$KERNELS")
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

## Debian/Ubuntu 相关
# Debian/Ubuntu Xanmod内核一把梭安装
# https://github.com/yumaoss/My_tools
debian_xanmod_install() {
    local XANMOD_VERSION

    pkg_install gnupg
    curl --retry 2 -sL https://dl.xanmod.org/archive.key | gpg --dearmor -vo /usr/share/keyrings/xanmod-archive-keyring.gpg --yes || \
    curl --retry 2 -sL "${GITHUB_PROXY}github.com/yumaoss/My_tools/raw/main/archive.key" | gpg --dearmor -vo /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
    # 添加xanmod存储库
    echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
    # 切换到官方脚本判断架构, 国内也许拉不下来增加重试
    # 如果官方check_x86-64_psabi.sh脚本无法拉取, 回退到yumaoss的备份仓库
    XANMOD_VERSION="$(curl --retry 2 -sL "https://dl.xanmod.org/check_x86-64_psabi.sh" | awk -f - 2>/dev/null | awk -F 'x86-64-v' '{print $2+0}')" || \
    XANMOD_VERSION="$(curl --retry 2 -sL "${GITHUB_PROXY}github.com/yumaoss/My_tools/raw/main/check_x86-64_psabi.sh" | awk -f - 2>/dev/null | awk -F 'x86-64-v' '{print $2+0}')"
    ([[ -n "$XANMOD_VERSION" && "$XANMOD_VERSION" =~ ^[0-9]$ ]] && pkg_install "linux-xanmod-x64v$XANMOD_VERSION") || die "failed to obtain xanmod version."
    bbr_menu
    os_reboot
}

# Debian/Ubuntu Xanmod内核安装交互菜单
debian_xanmod_menu() {
    local CHOICE

    # Xanmod架构仅支持amd64,  aarch64可以使用 bash <(curl -sL jhb.ovh/jb/bbrv3arm.sh) 但不确保是否安全, 待新增功能
    [ "$(dpkg --print-architecture 2>/dev/null)" != "amd64" ] && die "The system architecture is not supported."
    if dpkg -l | grep -qiE '^ii\s+linux-xanmod'; then
        _green "XanMod BBRv3 kernel detected."
        echo "Current kernel: $KERNEL_VERSION"
        separator
        echo "1. Update BBRv3 kernel"
        echo "2. Uninstall BBRv3 kernel"
        separator
        reading "Enter your choice: " CHOICE
        case "$CHOICE" in
            1 | "" ) pkg_uninstall "linux-*xanmod1*"; update-grub; debian_xanmod_install ;;
            2 ) pkg_uninstall "linux-*xanmod1*"; update-grub; os_reboot ;;
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

before_script() {
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

# 主程序运行前操作 (1/3)
before_script

# 解析命令行参数 (2/3)
# 存储非全局参数的参数数组, 用于后续逻辑
declare -a ARGS
# 处理全局选项
set -- "$@"
# shellcheck disable=SC2317
while [ "$#" -ge 1 ]; do
    case "$1" in
        -h | --help )
            show_usage
            shift
        ;;
        --debug )
            set -x
            shift
        ;;
        --bbr )
            BBR=1
            shift
        ;;
        --reboot )
            REBOOT=1
            shift
        ;;
        * )
            ARGS+=("$1")
            shift
        ;;
    esac
done

# 处理发行版参数
set -- "${ARGS[@]}"
# shellcheck disable=SC2317
while [ "$#" -ge 1 ]; do
    case "$1" in
        --almalinux | --centos | --fedora | --rhel | --rocky )
            shift
            KERNEL_CHANNEL="$1"
            rhel_install "$KERNEL_CHANNEL"
            shift
        ;;
        --debian | --ubuntu )
            debian_xanmod_install
            shift
        ;;
        * )
            die "Unexpected option: $1."
        ;;
    esac
done

# 默认交互逻辑 (3/3)
# 当没有任何参数时执行默认匹配逻辑
# 如果有全局参数已经被前面两个循环消耗, 此时位置参数为空
if [[ "$#" -eq 0 && "${#ARGS[@]}" -eq 0 ]]; then
    [[ "$OS_NAME" =~ ^(almalinux|centos|fedora|rhel|rocky)$ ]] && rhel_menu
    [[ "$OS_NAME" =~ ^(debian|ubuntu)$ ]] && debian_xanmod_menu
fi