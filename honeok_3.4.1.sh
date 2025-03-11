#!/usr/bin/env bash
#
# Description: lightweight Shell script toolbox designed for more convenient operations.
#
# Copyright (C) 2021 - 2025 honeok <honeok@duck.com>
#
# Acknowledgments and References:
# Teddysun <i@teddysun.com>
# kejilion <lion12776@outlook.com>
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

# shellcheck disable=all

readonly honeok_v='v3.4.1 (2025.03.11)'

red='\033[91m'
green='\033[92m'
yellow='\033[93m'
blue='\033[94m'
purple='\033[95m'
cyan='\033[96m'
white='\033[0m'
_red() { echo -e "${red}$*${white}"; }
_green() { echo -e "${green}$*${white}"; }
_yellow() { echo -e "${yellow}$*${white}"; }
_blue() { echo -e "${blue}$*${white}"; }
_purple() { echo -e "${purple}$*${white}"; }
_cyan() { echo -e "${cyan}$*${white}"; }

_err_msg() { echo -e "\033[41m\033[1m警告${white} $*"; }
_suc_msg() { echo -e "\033[42m\033[1m成功${white} $*"; }
_info_msg() { echo -e "\033[43m\033[1m提示${white} $*"; }

reading() { read -rep "$(_yellow "$1")" "$2"; }

short_line() { printf "%-20s\n" "-" | sed 's/\s/-/g'; }
long_line() { printf "%-40s\n" "-" | sed 's/\s/-/g'; }

# 预定义常量
os_info=$(grep "^PRETTY_NAME=" /etc/*-release | cut -d '"' -f 2 | sed 's/ (.*)//')
os_name=$(grep "^ID=" /etc/*-release | awk -F'=' '{print $2}' | sed 's/"//g')
honeok_pid='/tmp/honeok.pid'
UA_BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
readonly os_info os_name honeok_pid UA_BROWSER

# 预定义变量
github_Proxy='https://gh-proxy.com/'

if [ -f "$honeok_pid" ] && kill -0 "$(cat "$honeok_pid")" 2>/dev/null; then
    _err_msg "$(_red '脚本已经在运行! 如误判请反馈问题至: https://github.com/honeok/Tools/issues')" && exit 1
fi

echo $$ > "$honeok_pid"

_exit() {
    local result
    result=$?

    [ -f "$honeok_pid" ] && rm -f "$honeok_pid"
    [ -f "$HOME/get-docker.sh" ] && rm -f "$HOME/get-docker.sh"
    [ -f "/tmp/docker_ipv6.lock" ] && rm -f "/tmp/docker_ipv6.lock"
    [ -f "/etc/apt/sources.list.d/xanmod-release.list" ] && rm -f "/etc/apt/sources.list.d/xanmod-release.list"
    [ -f "$HOME/check_x86-64_psabi.sh" ] && rm -f "$HOME/check_x86-64_psabi.sh"
    [ -f "$HOME/upgrade_ssh.sh" ] && rm -f "$HOME/upgrade_ssh.sh"

    printf "\n" && exit "$result"
}

trap "_exit" SIGINT SIGQUIT SIGTERM EXIT

print_logo() {
    echo -e "$yellow   __                      __     \xf0\x9f\x92\x80
  / /  ___  ___  ___ ___  / /__
 / _ \/ _ \/ _ \/ -_) _ \/  '_/
/_//_/\___/_//_/\__/\___/_/\_\ 
"
    _green "当前操作系统: $os_info"
}

# 判断命令是否存在
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

# 运行预检, 全局变量定义
pre_check() {
    # 备用 www.qualcomm.cn
    # 备用 www.prologis.cn
    # 备用 www.garmin.com.cn
    # 备用 www.autodesk.com.cn
    # 备用 www.keysight.com.cn
    cloudflare_api='www.qualcomm.cn/cdn-cgi/trace'

    if [ "$(ps -p $$ -o comm=)" != "bash" ] || readlink /proc/$$/exe | grep -q "dash"; then
        _err_msg "$(_red '请使用bash运行此脚本!')" && exit 1
    fi

    ipv4_address=$(curl -A "$UA_BROWSER" -fskL -m 3 -4 "$cloudflare_api" | grep -i '^ip=' | cut -d'=' -f2 | xargs)
    ipv6_address=$(curl -A "$UA_BROWSER" -fskL -m 3 -6 "$cloudflare_api" | grep -i '^ip=' | cut -d'=' -f2 | xargs)

    # 获取服务器地区
    loc=$(curl -A "$UA_BROWSER" -fskL -m 3 "$cloudflare_api" | grep '^loc=' | cut -d'=' -f2 | xargs)
    [ -z "$loc" ] && { _err_msg "$(_red '无法获取服务器位置, 请检查网络后重试!')" && exit 1; }

    # 境外服务器仅ipv4访问测试通过后取消github代理
    if [ -n "$ipv4_address" ] && [ "$loc" != "CN" ]; then
        github_Proxy=''
    fi

    # 脚本当天及累计运行次数统计
    curl -fskL -m 2 --retry 1 "https://hit.forvps.gq/https://github.com/honeok/Tools/raw/master/honeok.sh" 2>&1 | grep -m1 -oE "[0-9]+[ ]+/[ ]+[0-9]+" >/dev/null 2>&1
}

# 获取虚拟化类型
virt_check() {
    local processor_type kernel_logs system_manufacturer system_product_name system_version

    processor_type=$(awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')

    if _exists "dmesg" >/dev/null 2>&1; then
        kernel_logs=$(dmesg 2>/dev/null)
    fi

    if _exists "dmidecode" >/dev/null 2>&1; then
        system_manufacturer=$(dmidecode -s system-manufacturer 2>/dev/null)
        system_product_name=$(dmidecode -s system-product-name 2>/dev/null)
        system_version=$(dmidecode -s system-version 2>/dev/null)
    fi

    if grep -qai docker /proc/1/cgroup; then
        virt_type="Docker"
    elif grep -qai lxc /proc/1/cgroup; then
        virt_type="LXC"
    elif grep -qai container=lxc /proc/1/environ; then
        virt_type="LXC"
    elif [ -f /proc/user_beancounters ]; then
        virt_type="OpenVZ"
    elif echo "$kernel_logs" | grep -qi "kvm-clock" 2>/dev/null; then
        virt_type="KVM"
    elif echo "$processor_type" | grep -qi "kvm" 2>/dev/null; then
        virt_type="KVM"
    elif echo "$processor_type" | grep -qi "qemu" 2>/dev/null; then
        virt_type="KVM"
    elif grep -qi "kvm" "/sys/devices/virtual/dmi/id/product_name" 2>/dev/null; then
        virt_type="KVM"
    elif grep -qi "qemu" "/proc/scsi/scsi" 2>/dev/null; then
        virt_type="KVM"
    elif echo "$kernel_logs" | grep -qi "vmware virtual platform" 2>/dev/null; then
        virt_type="VMware"
    elif echo "$kernel_logs" | grep -qi "parallels software international" 2>/dev/null; then
        virt_type="Parallels"
    elif echo "$kernel_logs" | grep -qi "virtualbox" 2>/dev/null; then
        virt_type="VirtualBox"
    elif [ -e /proc/xen ]; then
        if grep -qi "control_d" "/proc/xen/capabilities" 2>/dev/null; then
            virt_type="Xen-Dom0"
        else
            virt_type="Xen-DomU"
        fi
    elif [ -f "/sys/hypervisor/type" ] && grep -qi "xen" "/sys/hypervisor/type" 2>/dev/null; then
        virt_type="Xen"
    elif echo "$system_manufacturer" | grep -qi "microsoft corporation" 2>/dev/null; then
        if echo "$system_product_name" | grep -qi "virtual machine" 2>/dev/null; then
            if echo "$system_version" | grep -qi "7.0" 2>/dev/null || echo "$system_version" | grep -qi "hyper-v" 2>/dev/null; then
                virt_type="Hyper-V"
            else
                virt_type="Microsoft Virtual Machine"
            fi
        fi
    else
        virt_type="Dedicated"
    fi
}

to_kibyte() {
    awk "BEGIN {printf \"%.0f\", $1 / 1024}"
}

calc_sum() {
    local sum=0
    for num in "$@"; do
        sum=$(( sum + num ))
    done
    echo "$sum"
}

format_size() {
    # 获取字节
    local bytes="$1"
    local size=0
    local divisor=1
    local unit="KB"

    # 检查输入是否为非负整数
    if echo "$bytes" | grep -vE '^[0-9]+$' >/dev/null 2>&1; then
        return 1
    fi
    # 根据字节数大小选择单位和除数
    if [ "$bytes" -ge 1073741824 ]; then
        divisor=1073741824
        unit="TB"
    elif [ "$bytes" -ge 1048576 ]; then
        divisor=1048576
        unit="GB"
    elif [ "$bytes" -ge 1024 ]; then
        divisor=1024
        unit="MB"
    elif [ "$bytes" -eq 0 ]; then
        echo "$size"
        return 0
    fi
    # 计算并格式化结果保留一位小数
    size=$(awk "BEGIN {printf \"%.1f\", $bytes / $divisor}")
    echo "$size $unit"
}

# 系统信息
system_info() {
    virt_check

    local cpu_model cpu_cores cpu_frequency cpu_cache cpu_aes cpu_virt
    local mem_usage swap uswap
    local in_kernel_no_swap_total_size swap_total_size zfs_total_size disk_total_size in_kernel_no_swap_used_size swap_used_size zfs_used_size disk_used_size
    local boot_partition uptime_str load_average cpu_usage os_release cpu_architecture sys_bits kernel_version
    local congestion_algorithm queue_algorithm
    local total_recv total_sent
    local isp_info location system_time current_time

    # 获取CPU信息
    cpu_model=$(awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
    cpu_cores=$(awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo 2>/dev/null)
    cpu_frequency=$(awk -F: '/cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
    cpu_cache=$(awk -F: '/cache size/ {cache=$2} END {print cache}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
    cpu_aes=$(grep -i 'aes' /proc/cpuinfo) # 检查AES-NI指令集支持
    cpu_virt=$(grep -Ei 'vmx|svm' /proc/cpuinfo) # 检查VM-x/AMD-V支持

    # 内存和交换空间
    mem_usage=$(free -b | awk 'NR==2{printf "%.2f/%.2f MB (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')
    swap=$(format_size "$(free -k | awk '/Swap/ {print $2}')")
    swap_usage=$(format_size "$(free -k | awk '/Swap/ {print $3}')")

    # 获取并格式化磁盘空间使用情况
    # 磁盘大小 (包含swap和ZFS)
    in_kernel_no_swap_total_size=$(df -t simfs -t ext2 -t ext3 -t ext4 -t btrfs -t xfs -t vfat -t ntfs --total 2>/dev/null | awk '/total/ {print $2}')
    swap_total_size=$(free -k | awk '/Swap/ {print $2}')
    zfs_total_size=$(to_kibyte "$(calc_sum "$(zpool list -o size -Hp 2>/dev/null)")")
    disk_total_size=$(format_size $((swap_total_size + in_kernel_no_swap_total_size + zfs_total_size)))

    in_kernel_no_swap_used_size=$(df -t simfs -t ext2 -t ext3 -t ext4 -t btrfs -t xfs -t vfat -t ntfs --total 2>/dev/null | awk '/total/ {print $3}')
    swap_used_size=$(free -k | awk '/Swap/ {print $3}')
    zfs_used_size=$(to_kibyte "$(calc_sum "$(zpool list -o allocated -Hp 2>/dev/null)")")
    disk_used_size=$(format_size $((swap_used_size + in_kernel_no_swap_used_size + zfs_used_size)))

    # 启动盘路径
    boot_partition=$(findmnt -n -o SOURCE / 2>/dev/null || mount | grep ' / ' | awk '{print $1}')

    # 系统在线时间
    uptime_str=$(awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60} {printf("%d days %d hour %d min\n",a,b,c)}' /proc/uptime)

    # 获取负载平均值
    local load_average
    if _exists "w"; then
        load_average=$(w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
    elif _exists "uptime"; then
        load_average=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1, $2, $3}')
    fi

    # 计算CPU使用率
    cpu_usage=$(awk '
        NR==1 {idle1=$5; total1=$2+$3+$4+$5+$6+$7+$8+$9}
        NR==2 {
            diff=$2+$3+$4+$5+$6+$7+$8+$9 - total1
            printf "%.2f%%\n", diff ? 100*(1-($5-idle1)/diff) : 0
        }
    ' <(sleep 1; cat /proc/stat))

    # 获取操作系统版本信息
    if _exists "lsb_release" >/dev/null 2>&1; then
        os_release=$(lsb_release -d | awk -F: '{print $2}' | xargs | sed 's/ (.*)//')
    elif [ -f /etc/redhat-release ]; then
        os_release=$(awk '{print ($1, $3~/^[0-9]/ ? $3 : $4)}' /etc/redhat-release)
    elif [ -f /etc/os-release ]; then
        os_release=$(awk -F'[= "]' '/PRETTY_NAME/{print $3, $4, $5}' /etc/os-release)
    elif [ -f /etc/lsb-release ]; then
        os_release=$(awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release)
    else
        os_release="Unknown OS"
    fi

    # 获取CPU架构
    cpu_architecture=$(uname -m 2>/dev/null || lscpu | awk -F ': +' '/Architecture/{print $2}' || echo "Full Unknown")
    if _exists "getconf"; then
        sys_bits=$(getconf LONG_BIT)
    else
        echo "$cpu_architecture" | grep -q "64" && sys_bits="64" || sys_bits="32"
    fi
    # 获取内核版本信息
    if _exists "hostnamectl"; then
        kernel_version=$(hostnamectl | sed -n 's/^.*Kernel: Linux //p')
    else
        kernel_version=$(uname -r)
    fi

    # 获取网络拥塞控制算法
    # 获取队列算法
    if _exists "sysctl"; then
        congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
        queue_algorithm=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    fi

    # 获取出网入网数据
    bytes_to_gb() { echo $(( $1 / 1073741824 ))"."$(( $1 % 1073741824 * 100 / 1073741824 ))" GB"; } # 将字节数转换为GB
    # 总接收字节数 总发送字节数 初始为0
    total_recv=0;total_sent=0
    while read line; do
        set -- ${line#*:}
        total_recv=$((total_recv + $1))
        total_sent=$((total_sent + $9))
    done < <(grep ":" /proc/net/dev | grep -v "Inter|\ Receive")

    # 获取运营商信息
    isp_info=$(curl -A "$UA_BROWSER" -fskL -m 3 --connect-timeout 5 https://ipinfo.io/org)
    # 获取地理位置
    location=$(curl -A "$UA_BROWSER" -fskL -m 3 --connect-timeout 5 https://ipinfo.io/city)

    # 获取系统时区
    if grep -qi 'Alpine' /etc/issue 2>/dev/null; then
        system_time=$(date +"%Z %z")
    elif _exists timedatectl >/dev/null 2>&1; then
        system_time=$(timedatectl | awk '/Time zone/ {print $3}' | xargs)
    else
        system_time=$(date +"%Z %z")
    fi
    # 获取系统时间
    current_time=$(date '+%Y-%m-%d %H:%M:%S %Z')

    echo "系统信息查询"
    short_line
    echo " 主机名                : $(< /proc/sys/kernel/hostname)"
    echo " CPU 型号              : $cpu_model"
    echo " CPU 核心数            : $cpu_cores"
    echo " CPU 频率              : $cpu_frequency"
    echo " CPU 缓存              : $cpu_cache"
    if [ -n "$cpu_aes" ]; then
        echo -e " AES-NI指令集支持      : \xe2\x9c\x93 Enabled"
    else
        echo -e " AES-NI指令集支持      : \xe2\x9c\x97 Disabled"
    fi
    if [ -n "$cpu_virt" ]; then
        echo -e " VM-x / AMD-V支持      : \xe2\x9c\x93 Enabled"
    else
        echo -e " VM-x / AMD-V支持      : \xe2\x9c\x97 Disabled"
    fi
    echo " 物理内存              : $mem_usage"
    if [ "$swap" != "0" ];then
        echo " 虚拟内存              : $swap_usage"
    fi
    echo " 硬盘空间              : $disk_total_size ($disk_used_size Used)"
    echo " 启动盘路径            : $boot_partition"
    echo " 系统在线时间          : $uptime_str"
    echo " 负载 / CPU占用率      : $load_average / $cpu_usage"
    echo " 系统                  : $os_release"
    echo " 架构                  : $cpu_architecture ($sys_bits Bit)"
    echo " 内核                  : $kernel_version"
    echo " 网络拥塞控制算法      : $congestion_algorithm $queue_algorithm"
    echo " 网络接收数据量        : $(bytes_to_gb "$total_recv")"
    echo " 网络发送数据量        : $(bytes_to_gb "$total_sent")"
    echo " 虚拟化架构            : $virt_type"
    short_line
    echo " 运营商                : $isp_info"
    [ -n "$ipv4_address" ] && echo " 公网IPv4地址          : $ipv4_address"
    [ -n "$ipv6_address" ] && echo " 公网IPv6地址          : $ipv6_address"
    short_line
    echo " 地理位置              : $location"
    echo " 系统时区              : $system_time"
    echo " 系统时间              : $current_time"
    short_line
    echo ""
}

# 安全清屏
clear_screen() {
    if [ -t 1 ]; then
        tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
    fi
}

# 安装软件包
pkg_install() {
    for package in "$@"; do
        _yellow "Installing $package"
        if _exists dnf; then
            dnf install -y "$package"
        elif _exists yum; then
            yum install -y "$package"
        elif _exists apt; then
            DEBIAN_FRONTEND=noninteractive apt install -y -q "$package"
        elif _exists apt-get; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$package"
        elif _exists apk; then
            apk add --no-cache "$package"
        elif _exists pacman; then
            pacman -S --noconfirm --needed "$package"
        elif _exists zypper; then
            zypper install -y "$package"
        elif _exists opkg; then
            opkg install "$package"
        elif _exists pkg; then
            pkg install -y "$package"
        fi
    done
}

# 卸载软件包
pkg_uninstall() {
    for package in "$@"; do
        if _exists dnf; then
            dnf remove -y "$package"
        elif _exists yum; then
            yum remove -y "$package"
        elif _exists apt; then
            apt purge -y "$package"
        elif _exists apt-get; then
            apt-get purge -y "$package"
        elif _exists apk; then
            apk del "$package"
        elif _exists pacman; then
            pacman -Rns --noconfirm "$package"
        elif _exists zypper; then
            zypper remove -y "$package"
        elif _exists opkg; then
            opkg remove "$package"
        elif _exists pkg; then
            pkg delete -y "$package"
        fi
    done
}

# 通用systemctl函数, 适用于各种发行版
systemctl() {
    local _cmd="$1"
    local service_name="$2"
    local systemctl_cmd

    systemctl_cmd=$(which systemctl 2>/dev/null)
    if _exists "apk" >/dev/null 2>&1; then
        service "$service_name" "$_cmd"
    else
        "$systemctl_cmd" "$_cmd" "$service_name"
    fi
}

# 重载systemd管理的服务
daemon_reload() {
    local systemctl_cmd
    systemctl_cmd=$(which systemctl 2>/dev/null)

    if ! command -v apk >/dev/null 2>&1; then
        if command -v systemctl >/dev/null 2>&1; then
            "$systemctl_cmd" daemon-reload
        fi
    fi
}

disable() {
    local service_name="$1"
    local systemctl_cmd
    systemctl_cmd=$(which systemctl 2>/dev/null)

    if command -v apk >/dev/null 2>&1; then
        # Alpine使用OpenRC
        rc-update del "$service_name"
    else
        "$systemctl_cmd" disable "$service_name"
    fi
}

# 设置服务为开机自启
enable() {
    local service_name="$1"
    local systemctl_cmd
    systemctl_cmd=$(which systemctl 2>/dev/null)

    if command -v apk >/dev/null 2>&1; then
        if rc-update add "$service_name" default; then
            _suc_msg "$(_green "${service_name}已设置为开机自启")"
        else
            _err_msg "$(_red "${service_name}设置开机自启失败")"
        fi
    else
        if "$systemctl_cmd" enable "$service_name"; then
            _suc_msg "$(_green "${service_name}已设置为开机自启")"
        else
            _err_msg "$(_red "${service_name}设置开机自启失败")"
        fi
    fi
}

# 启动服务
start() {
    local service_name="$1"
    local systemctl_cmd
    systemctl_cmd=$(which systemctl 2>/dev/null)

    if command -v apk >/dev/null 2>&1; then
        if service "$service_name" start; then
            _suc_msg "$(_green "${service_name}已启动")"
        else
            _err_msg "$(_red "${service_name}启动失败")"
        fi
    else
        if "$systemctl_cmd" start "$service_name"; then
            _suc_msg "$(_green "${service_name}已启动")"
        else
            _err_msg "$(_red "${service_name}启动失败")"
        fi
    fi
}

# 停止服务
stop() {
    local service_name="$1"
    local systemctl_cmd
    systemctl_cmd=$(which systemctl 2>/dev/null)

    if command -v apk >/dev/null 2>&1; then
        if service "$service_name" stop; then
            _suc_msg "$(_green "${service_name}已停止")"
        else
            _err_msg "$(_red "${service_name}停止失败")"
        fi
    else
        if "$systemctl_cmd" stop "$service_name"; then
            _suc_msg "$(_green "${service_name}已停止")"
        else
            _err_msg "$(_red "${service_name}停止失败")"
        fi
    fi
}

# 重启服务
restart() {
    local service_name="$1"
    local systemctl_cmd
    systemctl_cmd=$(which systemctl 2>/dev/null)

    if command -v apk >/dev/null 2>&1; then
        if service "$service_name" restart; then
            _suc_msg "$(_green "${service_name}已重启")"
        else
            _err_msg "$(_red "${service_name}重启失败")"
        fi
    else
        if "$systemctl_cmd" restart "$service_name"; then
            _suc_msg "$(_green "${service_name}已重启")"
        else
            _err_msg "$(_red "${service_name}重启失败")"
        fi
    fi
}

# 重载服务
reload() {
    local service_name="$1"
    local systemctl_cmd
    systemctl_cmd=$(which systemctl 2>/dev/null)

    if command -v apk >/dev/null 2>&1; then
        if service "$service_name" reload; then
            _suc_msg "$(_green "${service_name}已重载")"
        else
            _err_msg "$(_red "${service_name}重载失败")"
        fi
    else
        if "$systemctl_cmd" reload "$service_name"; then
            _suc_msg "$(_green "${service_name}已重载")"
        else
            _err_msg "$(_red "${service_name}重载失败")"
        fi
    fi
}

# 查看服务状态
status() {
    local service_name="$1"
    local systemctl_cmd
    systemctl_cmd=$(which systemctl 2>/dev/null)

    if command -v apk >/dev/null 2>&1; then
        if service "$service_name" status; then
            _suc_msg "$(_green "${service_name}状态已显示")"
        else
            _err_msg "$(_red "${service_name}状态显示失败")"
        fi
    else
        if "$systemctl_cmd" status "$service_name"; then
            _suc_msg "$(_green "${service_name}状态已显示")"
        else
            _err_msg "$(_red "${service_name}状态显示失败")"
        fi
    fi
}

# 任意键结束
end_of() {
    echo "$(_green '操作完成')"
    echo "$(_yellow '按任意键继续')"
    read -n 1 -s -r -p ""
    printf "\n"
    clear_screen
}

# 检查用户是否为root
need_root() {
    clear_screen

    if [ "$(id -ru)" -ne "0" ] || [ "$EUID" -ne "0" ]; then
        _err_msg "$(_red '该功能需要root用户才能运行!')" && end_of && menu
    fi

    if [ "$(cd -P -- "$(dirname -- "$0")" && pwd -P)" != "/root" ]; then
        cd /root >/dev/null 2>&1 || { _err_msg "$(_red '切换目录失败!')"; return 1; }
    fi
}

# 定义全局脚本下载路径
set_script_dir() {
    local script_dir="/data/script"

    # 判断路径是否存在
    if [ ! -d "$script_dir" ]; then
        mkdir "$script_dir" -p >/dev/null 2>&1
        global_script_dir="$script_dir"
    else
        global_script_dir="$script_dir"
    fi
}

## 系统更新

# 修复dpkg中断问题
fix_dpkg() {
    local lockfiles=('/var/lib/dpkg/lock' '/var/lib/dpkg/lock-frontend')

    pkill -15 -x apt dpkg || pkill -9 -x apt dpkg

    for lockfile in "${lockfiles[@]}"; do
        if [ -f "$lockfile" ]; then
            rm -f "$lockfile" >/dev/null 2>&1
        fi
    done

    dpkg --configure -a
}

linux_update() {
    _yellow "正在系统更新"
    if command -v dnf >/dev/null 2>&1; then
        dnf -y update
    elif command -v yum >/dev/null 2>&1; then
        yum -y update
    elif command -v apt >/dev/null 2>&1; then
        fix_dpkg
        apt update
        apt -y full-upgrade
    elif command -v apk >/dev/null 2>&1; then
        apk update
        apk upgrade
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Syu --noconfirm
    elif command -v zypper >/dev/null 2>&1; then
        zypper refresh
        zypper update
    elif command -v opkg >/dev/null 2>&1; then
        opkg update
    elif command -v pkg >/dev/null 2>&1; then
        pkg update
        pkg -y upgrade
    else
        _red "未知的包管理器"
        return 1
    fi
    return 0
}

## 系统清理

linux_clean() {
    _yellow "正在系统清理"

    if command -v dnf >/dev/null 2>&1; then
        dnf -y autoremove
        dnf clean all
        dnf makecache
        journalctl --rotate
        journalctl --vacuum-time=3d # 删除所有早于3天前的日志
        journalctl --vacuum-size=200M
    elif command -v yum >/dev/null 2>&1; then
        yum -y autoremove
        yum clean all
        yum makecache
        journalctl --rotate
        journalctl --vacuum-time=3d
        journalctl --vacuum-size=200M
    elif command -v apt >/dev/null 2>&1; then
        fix_dpkg
        apt -y autoremove --purge
        apt -y clean
        apt -y autoclean
        journalctl --rotate
        journalctl --vacuum-time=3d
        journalctl --vacuum-size=200M
    elif command -v apk >/dev/null 2>&1; then
        apk cache clean
        rm -rf /var/log/*
        rm -rf /var/cache/apk/*
        rm -rf /tmp/*
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Rns "$(pacman -Qdtq)" --noconfirm
        pacman -Scc --noconfirm
        journalctl --rotate
        journalctl --vacuum-time=3d
        journalctl --vacuum-size=200M
    elif command -v zypper >/dev/null 2>&1; then
        zypper clean --all
        zypper refresh
        journalctl --rotate
        journalctl --vacuum-time=3d
        journalctl --vacuum-size=200M
    elif command -v opkg >/dev/null 2>&1; then
        rm -rf /var/log/*
        rm -rf /tmp/*
	elif command -v pkg >/dev/null 2>&1; then
		pkg -y autoremove
		pkg -y clean
		rm -rf /var/log/*
		rm -rf /tmp/*
    else
        _red "未知的包管理器"
        return 1
    fi
    return 0
}

## 常用工具

linux_tools() {
    while true; do
        clear_screen
        echo "▶ 基础工具"
        short_line
        echo "1. curl 下载工具                      2. wget下载工具"
        echo "3. sudo 超级管理权限工具              4. socat 通信连接工具"
        echo "5. htop 系统监控工具                  6. iftop 网络流量监控工具"
        echo "7. unzip ZIP压缩解压工具              8. tar GZ压缩解压工具"
        echo "9. tmux 多路后台运行工具              10. ffmpeg 视频编码直播推流工具"
        short_line
        echo "11. btop 现代化监控工具               12. ranger 文件管理工具"
        echo "13. Gdu 磁盘占用查看工具              14. fzf 全局搜索工具"
        echo "15. Vim文本编辑器                     16. nano文本编辑器"
        short_line
        echo "21. 黑客帝国屏保                      22. 跑火车屏保"
        echo "26. 俄罗斯方块小游戏                  27. 贪吃蛇小游戏"
        echo "28. 太空入侵者小游戏"
        short_line
        echo "31. 全部安装                          32. 全部安装 (不含屏保和游戏)"
        echo "33. 全部卸载"
        short_line
        echo "41. 安装指定工具                      42. 卸载指定工具"
        short_line
        echo "0. 返回主菜单"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1)
                clear_screen
                install curl
                clear_screen
                _yellow "工具已安装，使用方法如下:"
                curl --help
                ;;
            2)
                clear_screen
                install wget
                clear_screen
                _yellow "工具已安装，使用方法如下:"
                wget --help
                ;;
            3)
                clear_screen
                install sudo
                clear_screen
                _yellow "工具已安装，使用方法如下:"
                sudo --help
                ;;
            4)
                clear_screen
                install socat
                clear_screen
                _yellow "工具已安装，使用方法如下:"
                socat -h
                ;;
            5)
                clear_screen
                install htop
                clear_screen
                htop
                ;;
            6)
                clear_screen
                install iftop
                clear_screen
                iftop
                ;;
            7)
                clear_screen
                install unzip
                clear_screen
                _yellow "工具已安装，使用方法如下:"
                unzip
                ;;
            8)
                clear_screen
                install tar
                clear_screen
                _yellow "工具已安装，使用方法如下:"
                tar --help
                ;;
            9)
                clear_screen
                install tmux
                clear_screen
                _yellow "工具已安装，使用方法如下:"
                tmux --help
                ;;
            10)
                clear_screen
                install ffmpeg
                clear_screen
                _yellow "工具已安装，使用方法如下:"
                ffmpeg --help
                send_stats "安装ffmpeg"
                ;;
            11)
                clear_screen
                install btop
                clear_screen
                btop
                ;;
            12)
                clear_screen
                install ranger
                cd /
                clear_screen
                ranger
                cd ~ || { _err_msg "$(_red '切换目录失败！')"; return 1; }
                ;;
            13)
                clear_screen
                install gdu
                cd /
                clear_screen
                gdu
                cd ~ || { _err_msg "$(_red '切换目录失败！')"; return 1; }
                ;;
            14)
                clear_screen
                install fzf
                cd /
                clear_screen
                fzf
                cd ~ || { _err_msg "$(_red '切换目录失败！')"; return 1; }
                ;;
            15)
                clear_screen
                install vim
                cd /
                clear_screen
                vim -h
                cd ~ || { _err_msg "$(_red '切换目录失败！')"; return 1; }
                ;;
            16)
                clear_screen
                install nano
                cd /
                clear_screen
                nano -h
                cd ~ || { _err_msg "$(_red '切换目录失败！')"; return 1; }
                ;;
            21)
                clear_screen
                install cmatrix
                clear_screen
                cmatrix
                ;;
            22)
                clear_screen
                install sl
                clear_screen
                sl
                ;;
            26)
                clear_screen
                install bastet
                clear_screen
                bastet
                ;;
            27)
                clear_screen
                install nsnake
                clear_screen
                nsnake
                ;;
            28)
                clear_screen
                install ninvaders
                clear_screen
                ninvaders
                ;;
            31)
                clear_screen
                install curl wget sudo socat htop iftop unzip tar tmux ffmpeg btop ranger gdu fzf cmatrix sl bastet nsnake ninvaders vim nano
                ;;
            32)
                clear_screen
                install curl wget sudo socat htop iftop unzip tar tmux ffmpeg btop ranger gdu fzf vim nano
                ;;
            33)
                clear_screen
                remove htop iftop unzip tmux ffmpeg btop ranger gdu fzf cmatrix sl bastet nsnake ninvaders vim nano
                ;;
            41)
                clear_screen
                echo -n -e "${yellow}请输入安装的工具名 (wget curl sudo htop): ${white}"
                read -r installname
                install "$installname"
                ;;
            42)
                clear_screen
                echo -n -e "${yellow}请输入卸载的工具名 (htop ufw tmux cmatrix): ${white}"
                read -r removename
                remove "$removename"
                ;;
            0)
                menu
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
        end_of
    done
}

## BBR

linux_bbr() {
    local congestion_algorithm queue_algorithm choice

    clear_screen
    if [ -f "/etc/alpine-release" ]; then
        while true; do
            clear_screen
            congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
            queue_algorithm=$(sysctl -n net.core.default_qdisc)
            _yellow "当前TCP阻塞算法: ""$congestion_algorithm"" ""$queue_algorithm"""

            echo ""
            echo "BBR管理"
            short_line
            echo "1. 开启BBRv3              2. 关闭BBRv3(会重启)"
            short_line
            echo "0. 返回上一级选单"
            short_line

            reading '请输入选项并按回车键确认: ' choice

            case $choice in
                1)
                    bbr_on
                    ;;
                2)
                    sed -i '/net.ipv4.tcp_congestion_control=bbr/d' /etc/sysctl.conf
                    sysctl -p
                    server_reboot
                    ;;
                0)
                    break  # 跳出循环，退出菜单
                    ;;
                *)
                    _red "无效选项，请重新输入"
                    ;;
            esac
        done
    else
        install wget
        wget --no-check-certificate -O tcpx.sh "${github_Proxy}https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh" && chmod +x tcpx.sh && ./tcpx.sh
        rm -f tcpx.sh
    fi
}

## Docker

# Docker全局状态显示
docker_global_status() {
    local container_count image_count network_count volume_count

    container_count=$(docker ps -a -q 2>/dev/null | wc -l)
    image_count=$(docker images -q 2>/dev/null | wc -l)
    network_count=$(docker network ls -q 2>/dev/null | wc -l)
    volume_count=$(docker volume ls -q 2>/dev/null | wc -l)

    if command -v docker >/dev/null 2>&1; then
        short_line
        echo -e "${green}环境已经安装${white}  容器: ${green}${container_count}${white}  镜像: ${green}${image_count}${white}  网络: ${green}${network_count}${white}  容器卷: ${green}${volume_count}${white}"
    fi
}

install_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        install_add_docker
    else
        _green "Docker环境已经安装"
    fi
}

docker_version() {
    local docker_v=""
    local docker_compose_v=""

    # 获取Docker版本
    if command -v docker >/dev/null 2>&1; then
        docker_v=$(docker --version | awk -F '[ ,]' '{print $3}')
    elif command -v docker.io >/dev/null 2>&1; then
        docker_v=$(docker.io --version | awk -F '[ ,]' '{print $3}')
    fi

    # 获取Docker Compose版本
    if docker compose version >/dev/null 2>&1; then
        docker_compose_v=$(docker compose version --short)
    elif command -v docker-compose >/dev/null 2>&1; then
        docker_compose_v=$(docker-compose version --short)
    fi

    echo "Docker版本: v${docker_v}"
    echo "Docker Compose版本: v${docker_compose_v}"
}

install_docker_official() {
    if [[ "$country" == "CN" ]];then
        cd ~ || { _err_msg "$(_red '切换目录失败！')"; return 1; }
        # curl -fsL -o "get-docker.sh" "${github_Proxy}https://raw.githubusercontent.com/docker/docker-install/master/install.sh" && chmod +x get-docker.sh
        curl -fsL -o "get-docker.sh" "${github_Proxy}https://raw.githubusercontent.com/honeok/Tools/master/docker/install.sh" && chmod +x get-docker.sh
        sh get-docker.sh --mirror Aliyun
        rm -f get-docker.sh
    else
        curl -fsL https://get.docker.com | sh
    fi

    enable docker && start docker
}

install_add_docker() {
    if [ ! -f "/etc/alpine-release" ]; then
        _yellow "正在安装docker环境"
    fi

    # Docker调优
    install_common_docker() {
        generate_docker_config
        docker_version
    }

    if [ -f /etc/os-release ] && grep -q "Fedora" /etc/os-release; then
        install_docker_official
        install_common_docker
    elif command -v dnf >/dev/null 2>&1; then
        if ! dnf config-manager --help >/dev/null 2>&1; then
            install dnf-plugins-core
        fi

        for repo_file in /etc/yum.repos.d/docker*.repo; do
            [ -f "$repo_file" ] && rm -f "$repo_file" >/dev/null 2>&1
        done

        # 判断地区安装
        if [[ "$country" == "CN" ]];then
            dnf config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo >/dev/null 2>&1
        else
            dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo >/dev/null 2>&1
        fi

        install docker-ce docker-ce-cli containerd.io
        enable docker
        start docker
        install_common_docker
    elif [ -f /etc/os-release ] && grep -q "Kali" /etc/os-release; then
        install apt-transport-https ca-certificates curl gnupg lsb-release
        rm -f /usr/share/keyrings/docker-archive-keyring.gpg
        if [[ "$country" == "CN" ]];then
            if [ "$(uname -m)" = "x86_64" ]; then
                sed -i '/^deb \[arch=amd64 signed-by=\/etc\/apt\/keyrings\/docker-archive-keyring.gpg\] https:\/\/mirrors.aliyun.com\/docker-ce\/linux\/debian bullseye stable/d' /etc/apt/sources.list.d/docker.list >/dev/null 2>&1
                mkdir -p /etc/apt/keyrings
                curl -fsL https://mirrors.aliyun.com/docker-ce/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker-archive-keyring.gpg >/dev/null 2>&1
                echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker-archive-keyring.gpg] https://mirrors.aliyun.com/docker-ce/linux/debian bullseye stable" | tee /etc/apt/sources.list.d/docker.list >/dev/null 2>&1
            elif [ "$(uname -m)" = "aarch64" ]; then
                sed -i '/^deb \[arch=arm64 signed-by=\/etc\/apt\/keyrings\/docker-archive-keyring.gpg\] https:\/\/mirrors.aliyun.com\/docker-ce\/linux\/debian bullseye stable/d' /etc/apt/sources.list.d/docker.list >/dev/null 2>&1
                mkdir -p /etc/apt/keyrings
                curl -fsL https://mirrors.aliyun.com/docker-ce/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker-archive-keyring.gpg >/dev/null 2>&1
                echo "deb [arch=arm64 signed-by=/etc/apt/keyrings/docker-archive-keyring.gpg] https://mirrors.aliyun.com/docker-ce/linux/debian bullseye stable" | tee /etc/apt/sources.list.d/docker.list >/dev/null 2>&1
            fi
        else
            if [ "$(uname -m)" = "x86_64" ]; then
                sed -i '/^deb \[arch=amd64 signed-by=\/usr\/share\/keyrings\/docker-archive-keyring.gpg\] https:\/\/download.docker.com\/linux\/debian bullseye stable/d' /etc/apt/sources.list.d/docker.list >/dev/null 2>&1
                mkdir -p /etc/apt/keyrings
                curl -fsL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker-archive-keyring.gpg >/dev/null 2>&1
                echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian bullseye stable" | tee /etc/apt/sources.list.d/docker.list >/dev/null 2>&1
            elif [ "$(uname -m)" = "aarch64" ]; then
                sed -i '/^deb \[arch=arm64 signed-by=\/usr\/share\/keyrings\/docker-archive-keyring.gpg\] https:\/\/download.docker.com\/linux\/debian bullseye stable/d' /etc/apt/sources.list.d/docker.list >/dev/null 2>&1
                mkdir -p /etc/apt/keyrings
                curl -fsL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker-archive-keyring.gpg >/dev/null 2>&1
                echo "deb [arch=arm64 signed-by=/etc/apt/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian bullseye stable" | tee /etc/apt/sources.list.d/docker.list >/dev/null 2>&1
            fi
        fi
        install docker-ce docker-ce-cli containerd.io
        enable docker
        start docker
        install_common_docker
    elif command -v apt >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        install_docker_official
        install_common_docker
    else
        install docker docker-compose
        enable docker
        start docker
        install_common_docker
    fi
    sleep 2
}

# Docker调优
generate_docker_config() {
    local config_file config_dir is_china_server cgroup_driver

    config_file='/etc/docker/daemon.json'
    config_dir="$(dirname "$config_file")"
    is_china_server='false'

    install jq

    if ! command -v docker >/dev/null 2>&1; then
        _red "Docker未安装在系统上，无法优化"
        return 1
    fi

    if [ -f "$config_file" ]; then
        # 如果文件存在，检查是否已经优化过
        if grep -q '"default-shm-size": "128M"' "$config_file"; then
            _yellow "Docker配置文件已经优化，无需再次优化"
            return 0
        fi
    fi

    # 创建配置目录（如果不存在）
    if [ ! -d "$config_dir" ]; then
        mkdir -p "$config_dir"
    fi

    # 创建配置文件的基础配置（如果文件不存在）
    if [ ! -f "$config_file" ]; then
        echo "{}" > "$config_file"
    fi

    # 检查服务器是否在中国
    if [[ "$country" == "CN" ]];then
        is_china_server='true'
    fi

    # 获取 registry mirrors 内容
    registry_mirrors=$(curl -fsL "${github_Proxy}https://raw.githubusercontent.com/honeok/Tools/master/docker/registry_mirrors.txt" | grep -v '^#' | sed '/^$/d' | jq -R . | jq -s .)

    # 判断操作系统是否为 Alpine
    if grep -q 'Alpine' /etc/issue; then
        cgroup_driver="native.cgroupdriver=cgroupfs"
    else
        cgroup_driver="native.cgroupdriver=systemd"
    fi

    # 使用jq生成配置
    jq -n --argjson registry_mirrors "$registry_mirrors" \
        --arg cgroup_driver "$cgroup_driver" \
        --arg is_china_server "$is_china_server" \
        '{
            "exec-opts": [$cgroup_driver],
            "max-concurrent-downloads": 10,
            "max-concurrent-uploads": 5,
            "log-driver": "json-file",
            "log-opts": {
                "max-size": "30m",
                "max-file": "3"
            },
            "storage-driver": "overlay2",
            "default-shm-size": "128M",
            "debug": false,
            "ipv6": false
        } as $base_config |
        if ($is_china_server == "true") and ($registry_mirrors | length > 0) then
            { "registry-mirrors": $registry_mirrors } + $base_config
        else
            $base_config
        end' > "$config_file"

    # 校验和重新加载Docker守护进程
    _green "Docker配置文件已重新加载并重启Docker服务"
    daemon_reload
    restart docker
    echo "Docker配置文件已根据服务器IP归属做相关优化"
    echo "配置文件默认关闭Docker IPv6，如需调整自行修改${config_file}"
}

restart_docker_retry() {
    local attempt=0
    local max_retries=5
    local retry_delay=2

    daemon_reload
    while (( attempt < max_retries )); do
        if restart docker >/dev/null 2>&1; then
            return 0  # 重启成功，返回
        fi
        (( attempt++ ))
        echo -e "${red}重启Docker失败，正在重试 (尝试次数: $attempt)${white}"
        sleep "$retry_delay"
    done
    _err_msg "$(_red '重启Docker失败，超过最大重试次数！')"
    return 1
}

docker_ipv6_on() {
    need_root
    install jq

    local config_file="/etc/docker/daemon.json"
    local required_ipv6_config='{"ipv6": true, "fixed-cidr-v6": "2001:db8:1::/64"}'
    local lock_file="/tmp/docker_ipv6.lock"

    # 检查锁文件是否存在，以及Docker启动状态
    if [ -f "$lock_file" ] || \
        ! docker info >/dev/null 2>&1 || \
        # 检查Docker API是否可用
        ! curl -s --unix-socket /var/run/docker.sock http://localhost/version >/dev/null 2>&1; then
        _red "请不要在短时间重复开关会导致docker启动失败！"
        return 1
    fi

    # 检查配置文件是否存在，如果不存在则创建文件并写入默认设置
    if [ ! -f "$config_file" ]; then
        echo "$required_ipv6_config" | jq . > "$config_file"
        restart_docker_retry
    else
        local original_config current_ipv6

        # 使用jq处理配置文件的更新
        original_config=$(<"$config_file")

        # 检查当前配置是否已经有ipv6设置
        current_ipv6=$(echo "$original_config" | jq '.ipv6 // false')

        # 更新配置，开启IPv6
        if [[ "$current_ipv6" == "false" ]]; then
            updated_config=$(echo "$original_config" | jq '. + {ipv6: true, "fixed-cidr-v6": "2001:db8:1::/64"}')
        else
            updated_config=$(echo "$original_config" | jq '. + {"fixed-cidr-v6": "2001:db8:1::/64"}')
        fi

        # 对比原始配置与新配置
        if [[ "$original_config" == "$updated_config" ]]; then
            _yellow "当前已开启ipv6访问"
        else
            echo "$updated_config" | jq . > "$config_file"
            restart_docker_retry
            _green "已成功开启ipv6访问"

            # 创建锁文件
            touch "$lock_file"
            # 等待6秒后删除锁文件
            (sleep 6 && rm -f "$lock_file") &
        fi
    fi
}

docker_ipv6_off() {
    need_root
    install jq

    local config_file="/etc/docker/daemon.json"
    local lock_file="/tmp/docker_ipv6.lock"

    local original_config updated_config current_ipv6

    # 检查锁文件是否存在，以及Docker启动状态
    if [ -f "$lock_file" ] || \
        ! docker info >/dev/null 2>&1 || \
        # 检查Docker API是否可用
        ! curl -s --unix-socket /var/run/docker.sock http://localhost/version >/dev/null 2>&1; then
        _red "请不要在短时间重复开关会导致docker启动失败！"
        return 1
    fi

    # 检查配置文件是否存在
    if [ ! -f "$config_file" ]; then
        _red "配置文件不存在"
        return 1
    fi

    # 读取当前配置
    original_config=$(<"$config_file")
    # 使用jq处理配置文件的更新
    updated_config=$(echo "$original_config" | jq 'del(.["fixed-cidr-v6"]) | .ipv6 = false')
    # 检查当前的 ipv6 状态
    current_ipv6=$(echo "$original_config" | jq -r '.ipv6 // false')

    # 对比原始配置与新配置
    if [[ "$current_ipv6" == "false" ]]; then
        _yellow "当前已关闭ipv6访问"
    else
        echo "$updated_config" | jq . > "$config_file"
        restart_docker_retry
        _green "已成功关闭ipv6访问"

        # 创建锁文件
        touch "$lock_file"
        # 等待 6 秒后删除锁文件
        (sleep 6 && rm -f "$lock_file") &
    fi
}

# 卸载Docker
uninstall_docker() {
    local docker_data_files=("/var/lib/docker" "/var/lib/containerd" "/etc/docker" "/opt/containerd" "/data/docker_data")
    local docker_depend_files=("/etc/yum.repos.d/docker*" "/etc/apt/sources.list.d/docker.*" "/etc/apt/keyrings/docker.*" "/var/log/docker.*")
    local binary_files=("/usr/bin/docker" "/usr/bin/docker-compose")  # 删除二进制文件路径

    need_root

    # 停止并删除Docker服务和容器
    stop_and_remove_docker() {
        local running_containers
        running_containers=$(docker ps -aq)
        [ -n "$running_containers" ] && docker rm -f "$running_containers" >/dev/null 2>&1
        stop docker >/dev/null 2>&1
        disable docker >/dev/null 2>&1
    }

    # 移除Docker文件和仓库文件
    cleanup_files() {
        for pattern in "${docker_depend_files[@]}"; do
            for file in $pattern; do
                [ -e "$file" ] && rm -rf "$file" >/dev/null 2>&1
            done
        done

        for file in "${docker_data_files[@]}" "${binary_files[@]}"; do
            [ -e "$file" ] && rm -rf "$file" >/dev/null 2>&1
        done
    }

    # 检查Docker是否安装
    if ! command -v docker >/dev/null 2>&1; then
        _red "Docker未安装在系统上，无法继续卸载"
        return 1
    fi

    stop_and_remove_docker

    remove docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras
    cleanup_files

    # 清除命令缓存
    hash -r

    sleep 2

    # 检查卸载是否成功
    if command -v docker >/dev/null 2>&1 || [ -e "/usr/bin/docker" ]; then
        _red "Docker卸载失败，请手动检查"
        return 1
    else
        _green "Docker和Docker Compose已卸载，并清理文件夹和相关依赖"
    fi
}

docker_ps() {
    while true; do
        clear_screen
        echo "Docker容器列表"
        docker ps -a
        echo ""
        echo "容器操作"
        short_line
        echo "1. 创建新的容器"
        short_line
        echo "2. 启动指定容器             6. 启动所有容器"
        echo "3. 停止指定容器             7. 停止所有容器"
        echo "4. 删除指定容器             8. 删除所有容器"
        echo "5. 重启指定容器             9. 重启所有容器"
        short_line
        echo "11. 进入指定容器            12. 查看容器日志"
        echo "13. 查看容器网络            14. 查看容器占用"
        short_line
        echo "0. 返回上一级选单"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1)
                echo -n "请输入创建命令:"
                read -r dockername
                "$dockername"
                ;;
            2)
                echo -n "请输入容器名(多个容器名请用空格分隔): "
                read -r dockername
                docker start "$dockername"
                ;;
            3)
                echo -n "请输入容器名(多个容器名请用空格分隔): "
                read -r dockername
                docker stop "$dockername"
                ;;
            4)
                echo -n "请输入容器名(多个容器名请用空格分隔): "
                read -r dockername
                docker rm -f "$dockername"
                ;;
            5)
                echo -n "请输入容器名(多个容器名请用空格分隔): "
                read -r dockername
                docker restart "$dockername"
                ;;
            6)
                docker start "$(docker ps -a -q)"
                ;;
            7)
                docker stop "$(docker ps -q)"
                ;;
            8)
                echo -n -e "${yellow}确定删除所有容器吗? (y/n): ${white}"
                read -r choice

                case $choice in
                    [Yy])
                        docker rm -f "$(docker ps -a -q)"
                        ;;
                    [Nn])
                        ;;
                    *)
                        _red "无效选项，请重新输入"
                        ;;
                esac
                ;;
            9)
                docker restart "$(docker ps -q)"
                ;;
            11)
                echo -n "请输入容器名:"
                read -r dockername
                docker exec -it "$dockername" /bin/sh
                end_of
                ;;
            12)
                echo -n "请输入容器名:"
                read -r dockername
                docker logs "$dockername"
                end_of
                ;;
            13)
                echo ""
                container_ids=$(docker ps -q)
                long_line
                printf "%-25s %-25s %-25s\n" "容器名称" "网络名称" "IP地址"
                for container_id in $container_ids; do
                    container_info=$(docker inspect --format '{{ .Name }}{{ range $network, $config := .NetworkSettings.Networks }} {{ $network }} {{ $config.IPAddress }}{{ end }}' "$container_id")
                    container_name=$(echo "$container_info" | awk '{print $1}')
                    network_info=$(echo "$container_info" | cut -d' ' -f2-)
                    while IFS= read -r line; do
                        network_name=$(echo "$line" | awk '{print $1}')
                        ip_address=$(echo "$line" | awk '{print $2}')
                        printf "%-20s %-20s %-15s\n" "$container_name" "$network_name" "$ip_address"
                    done <<< "$network_info"
                done
                end_of
                ;;
            14)
                docker stats --no-stream
                end_of
                ;;
            0)
                break
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
    done
}

docker_image() {
    while true; do
        clear_screen
        echo "Docker镜像列表"
        docker image ls
        echo ""
        echo "镜像操作"
        short_line
        echo "1. 获取指定镜像             3. 删除指定镜像"
        echo "2. 更新指定镜像             4. 删除所有镜像"
        short_line
        echo "0. 返回上一级选单"
        short_line

        reading '请输入选项并按回车键确认: ' choice
        case $choice in
            1)
                echo -n "请输入镜像名(多个镜像名请用空格分隔): "
                read -r imagenames
                for name in $imagenames; do
                    echo -e "${yellow}正在获取镜像: $name${white}"
                    docker pull "$name"
                done
                ;;
            2)
                echo -n "请输入镜像名(多个镜像名请用空格分隔): "
                read -r imagenames
                for name in $imagenames; do
                    echo -e "${yellow}正在更新镜像: $name${white}"
                    docker pull "$name"
                done
                ;;
            3)
                echo -n "请输入镜像名(多个镜像名请用空格分隔): "
                read -r imagenames
                for name in $imagenames; do
                    docker rmi -f "$name"
                done
                ;;
            4)
                echo -n -e "${red}确定删除所有镜像吗? (y/n): ${white}"
                read -r choice

                case $choice in
                    [Yy])
                        if [ -n "$(docker images -q)" ]; then
                            docker rmi -f "$(docker images -q)"
                        else
                            _yellow "没有镜像可删除"
                        fi
                        ;;
                    [Nn])
                        _yellow "操作已取消"
                        ;;
                    *)
                        _red "无效选项，请重新输入"
                        ;;
                esac
                ;;
            0)
                break
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
    done
}

docker_manager() {
    while true; do
        clear_screen
        echo "▶ Docker管理"
        docker_global_status
        short_line
        echo "1. 安装更新Docker环境"
        short_line
        echo "2. 查看Docker全局状态"
        short_line
        echo "3. Docker容器管理 ▶"
        echo "4. Docker镜像管理 ▶"
        echo "5. Docker网络管理 ▶"
        echo "6. Docker卷管理 ▶"
        short_line
        echo "7. 清理无用的docker容器和镜像网络数据卷"
        short_line
        echo "8. 更换Docker源"
        echo "9. 编辑Docker配置文件"
        echo "10. Docker配置文件一键优化 (CN提供镜像加速)"
        short_line
        echo "11. 开启Docker-ipv6访问"
        echo "12. 关闭Docker-ipv6访问"
        short_line
        echo "20. 卸载Docker环境"
        short_line
        echo "0. 返回主菜单"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1)
                clear_screen
                if ! command -v docker >/dev/null 2>&1; then
                    install_add_docker
                else
                    docker_version
                    while true; do
                        echo -n -e "${yellow}是否升级Docker环境? (y/n): ${white}"
                        read -r answer

                        case $answer in
                            [Y/y])
                                install_add_docker
                                break
                                ;;
                            [N/n])
                                break
                                ;;
                            *)
                                _red "无效选项，请重新输入"
                                ;;
                        esac
                    done
                fi
                ;;
            2)
                clear_screen
                local image_count container_count network_count volume_count

                image_count=$(docker images -q 2>/dev/null | wc -l)
                container_count=$(docker ps -a -q 2>/dev/null | wc -l)
                network_count=$(docker network ls -q 2>/dev/null | wc -l)
                volume_count=$(docker volume ls -q 2>/dev/null | wc -l)

                # 显示镜像、容器、卷和网络列表
                for resource in "镜像列表" "容器列表" "卷列表" "网络列表"; do
                    case "$resource" in
                        "镜像列表") count_var=$image_count ;;
                        "容器列表") count_var=$container_count ;;
                        "卷列表") count_var=$volume_count ;;
                        "网络列表") count_var=$network_count ;;
                    esac

                    echo "Docker${resource}:"
                    if [ "$count_var" -gt 0 ]; then
                        case "$resource" in
                            "镜像列表") docker image ls ;;
                            "容器列表") docker ps -a ;;
                            "卷列表") docker volume ls ;;
                            "网络列表") docker network ls ;;
                        esac
                    else
                        _red "None"
                    fi
                    echo ""
                done
                ;;
            3)
                docker_ps
                ;;
            4)
                docker_image
                ;;
            5)
                while true; do
                    clear_screen
                    echo "Docker网络列表"
                    long_line
                    docker network ls
                    echo ""
                    long_line
                    container_ids=$(docker ps -q)
                    printf "%-25s %-25s %-25s\n" "容器名称" "网络名称" "IP地址"

                    for container_id in $container_ids; do
                        container_info=$(docker inspect --format '{{ .Name }}{{ range $network, $config := .NetworkSettings.Networks }} {{ $network }} {{ $config.IPAddress }}{{ end }}' "$container_id")
                        container_name=$(echo "$container_info" | awk '{print $1}')
                        network_info=$(echo "$container_info" | cut -d' ' -f2-)

                        while IFS= read -r line; do
                            network_name=$(echo "$line" | awk '{print $1}')
                            ip_address=$(echo "$line" | awk '{print $2}')

                            printf "%-20s %-20s %-15s\n" "$container_name" "$network_name" "$ip_address"
                        done <<< "$network_info"
                    done

                    echo ""
                    echo "网络操作"
                    short_line
                    echo "1. 创建网络"
                    echo "2. 加入网络"
                    echo "3. 退出网络"
                    echo "4. 删除网络"
                    short_line
                    echo "0. 返回上一级选单"
                    short_line

                    reading '请输入选项并按回车键确认: ' choice

                    case $choice in
                        1)
                            echo -n "设置新网络名:"
                            read -r dockernetwork
                            docker network create "$dockernetwork"
                            ;;
                        2)
                            echo -n "设置新网络名:"
                            read -r dockernetwork
                            echo -n "设置新网络名:"
                            read -r dockernames

                            for dockername in $dockernames; do
                                docker network connect "$dockernetwork" "$dockername"
                            done                  
                            ;;
                        3)
                            echo -n "设置新网络名:"
                            read -r dockernetwork

                            echo -n "哪些容器退出该网络(多个容器名请用空格分隔): "
                            read -r dockernames
                            
                            for dockername in $dockernames; do
                                docker network disconnect "$dockernetwork" "$dockername"
                            done
                            ;;
                        4)
                            echo -n "请输入要删除的网络名:"
                            read -r dockernetwork
                            docker network rm "$dockernetwork"
                            ;;
                        0)
                            break  # 跳出循环,退出菜单
                            ;;
                        *)
                            _red "无效选项，请重新输入"
                            ;;
                    esac
                done
                ;;
            6)
                while true; do
                    clear_screen
                    echo "Docker卷列表"
                    docker volume ls
                    echo ""
                    echo "卷操作"
                    short_line
                    echo "1. 创建新卷"
                    echo "2. 删除指定卷"
                    echo "3. 删除所有卷"
                    short_line
                    echo "0. 返回上一级选单"
                    short_line

                    reading '请输入选项并按回车键确认: ' choice

                    case $choice in
                        1)
                            echo -n "设置新卷名:"
                            read -r dockerjuan
                            docker volume create "$dockerjuan"
                            ;;
                        2)
                            echo -n "输入删除卷名(多个卷名请用空格分隔): "
                            read -r dockerjuans

                            for dockerjuan in $dockerjuans; do
                                docker volume rm "$dockerjuan"
                            done
                            ;;
                        3)
                            echo -n "确定删除所有未使用的卷吗:"
                            read -r choice
                            case $choice in
                                [Yy])
                                    docker volume prune -f
                                    ;;
                                [Nn])
                                    ;;
                                *)
                                    _red "无效选项，请重新输入"
                                    ;;
                            esac
                            ;;
                        0)
                            break  # 跳出循环,退出菜单
                            ;;
                        *)
                            _red "无效选项，请重新输入"
                            ;;
                    esac
                done
                ;;
            7)
                clear_screen
                echo -n -e "${yellow}将清理无用的镜像容器网络，包括停止的容器，确定清理吗? (y/n): ${white}"
                read -r choice

                case $choice in
                    [Yy])
                        docker system prune -af --volumes
                        ;;
                    [Nn])
                        ;;
                    *)
                        _red "无效选项，请重新输入"
                        ;;
                esac
                ;;
            8)
                clear_screen
                bash <(curl -sSL https://linuxmirrors.cn/docker.sh)
                ;;
            9)
                clear_screen
                mkdir -p /etc/docker && vim /etc/docker/daemon.json
                restart docker
                ;;
            10)
                generate_docker_config
                ;;
            11)
                clear_screen
                docker_ipv6_on
                ;;
            12)
                clear_screen
                docker_ipv6_off
                ;;
            20)
                clear_screen
                echo -n -e "${yellow}确定卸载docker环境吗? (y/n): ${white}"
                read -r choice

                case $choice in
                    [Yy])
                        uninstall_docker
                        ;;
                    [Nn])
                        ;;
                    *)
                        _red "无效选项，请重新输入"
                        ;;
                esac
                ;;
            0)
                menu
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
        end_of
    done
}

## LDNMP

docker_compose() {
    local docker_compose_cmd
    # 检查 docker compose 版本
    if docker compose version >/dev/null 2>&1; then
        docker_compose_cmd="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker_compose_cmd="docker-compose"
    fi

    case "$1" in
        start)    # 启动容器
            $docker_compose_cmd up -d
            ;;
        restart)
            $docker_compose_cmd restart
            ;;
        stop)    # 停止容器
            $docker_compose_cmd stop
            ;;
        recreate)
            $docker_compose_cmd up -d --force-recreate
            ;;
        down)    # 停止并删除容器
            $docker_compose_cmd down
            ;;
        pull)
            $docker_compose_cmd pull
            ;;
        down_all) # 停止并删除容器、镜像、卷、未使用的网络
            $docker_compose_cmd down --rmi all --volumes --remove-orphans
            ;;
        version)
            $docker_compose_cmd version
            ;;
    esac
}

iptables_open() {
    local table
    for table in iptables ip6tables; do
        if ! command -v $table >/dev/null 2>&1; then
            continue
        fi

        $table -P INPUT ACCEPT >/dev/null 2>&1
        $table -P FORWARD ACCEPT >/dev/null 2>&1
        $table -P OUTPUT ACCEPT >/dev/null 2>&1
        $table -F >/dev/null 2>&1
    done
}

fail2ban_status() {
    docker restart fail2ban >/dev/null 2>&1

    # 初始等待3秒，确保容器有时间启动
    sleep 3

    # 定义最大重试次数和每次检查的间隔时间
    local retries=5  # 最多重试5次
    local interval=1  # 每次检查间隔1秒
    local count=0

    while [ $count -lt $retries ]; do
        # 捕获结果
        if docker exec fail2ban fail2ban-client status >/dev/null 2>&1; then
            # 如果命令成功执行，显示fail2ban状态并退出循环
            docker exec fail2ban fail2ban-client status
            return 0
        else
            # 如果失败输出提示信息并等待
            _yellow "fail2Ban 服务尚未完全启动，重试中($((count+1))/$retries)"
        fi

        sleep $interval
        count=$((count + 1))
    done

    # 如果多次检测后仍未成功,输出错误信息
    _red "fail2ban容器在重试后仍未成功运行！"
}

fail2ban_status_jail() {
    docker exec fail2ban fail2ban-client status $jail_name
}

fail2ban_sshd() {
    if grep -q 'Alpine' /etc/issue; then
        jail_name=alpine-sshd
        fail2ban_status_jail
    elif command -v dnf >/dev/null 2>&1; then
        jail_name=centos-sshd
        fail2ban_status_jail
    else
        jail_name=linux-sshd
        fail2ban_status_jail
    fi
}

fail2ban_install_sshd() {
    local fail2ban_dir="/data/docker_data/fail2ban"
    local config_dir="$fail2ban_dir/config/fail2ban"

    if [ ! -d "$fail2ban_dir" ]; then
        mkdir -p "$fail2ban_dir"
    fi

    cd "$fail2ban_dir" || { _err_msg "$(_red '切换目录失败！')"; return 1; }

    curl -fsL -o "docker-compose.yml" "${github_Proxy}https://raw.githubusercontent.com/honeok/config/master/fail2ban/ldnmp-docker-compose.yml"

    docker_compose start

    sleep 3
    if grep -q 'Alpine' /etc/issue; then
        cd "$config_dir/filter.d" || { _err_msg "$(_red '切换目录失败！')"; return 1; }
        curl -fsL -O "${github_Proxy}https://raw.githubusercontent.com/kejilion/config/main/fail2ban/alpine-sshd.conf"
        curl -fsL -O "${github_Proxy}https://raw.githubusercontent.com/kejilion/config/main/fail2ban/alpine-sshd-ddos.conf"
        cd "$config_dir/jail.d/" || { _err_msg "$(_red '切换目录失败！')"; return 1; }
        curl -fsL -O "${github_Proxy}https://raw.githubusercontent.com/kejilion/config/main/fail2ban/alpine-ssh.conf"
    elif command -v dnf >/dev/null 2>&1; then
        cd "$config_dir/jail.d/" || { _err_msg "$(_red '切换目录失败！')"; return 1; }
        curl -fsL -O "${github_Proxy}https://raw.githubusercontent.com/kejilion/config/main/fail2ban/centos-ssh.conf"
    else
        install rsyslog
        systemctl start rsyslog
        systemctl enable rsyslog
        cd "$config_dir/jail.d/" || { _err_msg "$(_red '切换目录失败！')"; return 1; }
        curl -fsL -O "${github_Proxy}https://raw.githubusercontent.com/kejilion/config/main/fail2ban/linux-ssh.conf"
    fi
}

## 系统工具

restart_ssh() {
    restart sshd ssh >/dev/null 2>&1
}

add_sshpasswd() {
    _yellow "设置你的root密码"
    passwd

    # 处理SSH配置文件以允许root登录和密码认证
    # 修改PermitRootLogin
    if ! grep -qE '^\s*PermitRootLogin.*' /etc/ssh/sshd_config; then
        # 如果没有找到PermitRootLogin，则添加新行
        echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
    else
        # 如果存在但被注释，则取消注释并将值改为 yes
        sed -i 's/^\(\s*#\s*\)\?\(PermitRootLogin\s*.*\)/PermitRootLogin yes/' /etc/ssh/sshd_config
    fi

    # 取消注释并启用 PasswordAuthentication
    if ! grep -qE '^\s*PasswordAuthentication\s+' /etc/ssh/sshd_config; then
        # 如果没有找到 PasswordAuthentication，则添加新行
        echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    else
        # 如果存在但被注释，则取消注释并设置为 yes
        sed -i 's/^\(\s*#\s*\)\?\(PasswordAuthentication\s*.*\)/PasswordAuthentication yes/' /etc/ssh/sshd_config
    fi

    # 清理不再使用的SSH配置文件目录
    rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/* >/dev/null 2>&1

    restart_ssh
    _green "root登录设置完毕！"
}

# 备份DNS配置文件
bak_dns() {
    # 定义源文件和备份文件的位置
    local dns_config="/etc/resolv.conf"
    local backupdns_config="/etc/resolv.conf.bak"

    # 检查源文件是否存在并执行备份
    if [[ -f "$dns_config" ]]; then
        cp "$dns_config" "$backupdns_config" || { _red "备份DNS配置文件失败"; return 1; }
    else
        _red "DNS配置文件不存在"
        return 1
    fi
}

set_dns() {
    local cloudflare_ipv4="1.1.1.1"
    local google_ipv4="8.8.8.8"
    local cloudflare_ipv6="2606:4700:4700::1111"
    local google_ipv6="2001:4860:4860::8888"

    local ali_ipv4="223.5.5.5"
    local tencent_ipv4="183.60.83.19"
    local ali_ipv6="2400:3200::1"
    local tencent_ipv6="2400:da00::6666"

    if [[ "$country" == "CN" ]];then
        {
            echo "nameserver $ali_ipv4"
            echo "nameserver $tencent_ipv4"
            if [[ $(ip -6 addr | grep -c "inet6") -gt 0 ]]; then
                echo "nameserver $ali_ipv6"
                echo "nameserver $tencent_ipv6"
            fi
        } | tee /etc/resolv.conf >/dev/null
    else
        {
            echo "nameserver $cloudflare_ipv4"
            echo "nameserver $google_ipv4"
            if [[ $(ip -6 addr | grep -c "inet6") -gt 0 ]]; then
                echo "nameserver $cloudflare_ipv6"
                echo "nameserver $google_ipv6"
            fi
        } | tee /etc/resolv.conf >/dev/null
    fi
}

# 回滚到备份的DNS配置文件
rollbak_dns() {
    # 定义源文件和备份文件的位置
    local dns_config="/etc/resolv.conf"
    local backupdns_config="/etc/resolv.conf.bak"

    # 查找备份文件并执行恢复操作
    if [[ -f "$backupdns_config" ]]; then
        if cp "$backupdns_config" "$dns_config"; then
            rm -f "$backupdns_config"
        else
            _red "恢复文件失败"
        fi
    else
        _red "未找到DNS配置文件备份"
    fi
}

dns_lock() {
    if lsattr /etc/resolv.conf | grep -qi 'i'; then
        if chattr -i /etc/resolv.conf; then
            _green "DNS文件已解锁，可以被修改"
        else
            _red "解锁DNS文件失败"
        fi
    else
        if chattr +i /etc/resolv.conf; then
            _green "DNS 文件已锁定，防止其他服务修改"
        else
            _red "锁定DNS文件失败"
        fi
    fi
}

reinstall_system() {
    local os_text="当前操作系统: $os_info"
    local current_sshport
    local choice
    local web_content iso_link

    current_sshport=$(grep -E '^[^#]*Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}' | head -n 1)
    [ -z "$current_sshport" ] && current_sshport=22

    script_MollyLau() {
        curl -fskL -O InstallNET.sh "${github_Proxy}https://raw.githubusercontent.com/leitbogioro/Tools/master/Linux_reinstall/InstallNET.sh" && chmod +x InstallNET.sh
    }

    script_bin456789() {
        if [ "$loc" == "CN" ];then
            curl -fsL -O https://jihulab.com/bin456789/reinstall/-/raw/main/reinstall.sh || wget -O reinstall.sh "$_" && chmod +x reinstall.sh
        else
            curl -fsL -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh || wget -O reinstall.sh "$_" && chmod +x reinstall.sh
        fi
    }

    reinstall_linux_MollyLau() {
        echo "重装后初始用户名: $(_yellow 'root') 初始密码: $(_yellow 'LeitboGi0ro') 初始端口: $(_yellow "$current_sshport")"
        echo "$(_yellow '按任意键继续')"
        read -n 1 -s -r -p ""
        script_MollyLau
    }

    reinstall_win_MollyLau() {
        echo "重装后初始用户名: $(_yellow 'Administrator') 初始密码: $(_yellow 'Teddysun.com') 初始端口: $(_yellow '3389')"
        echo "$(_yellow '按任意键继续')"
        read -n 1 -s -r -p ""
        script_MollyLau
    }

    reinstall_linux_bin456789() {
        echo "重装后初始用户名: $(_yellow 'root') 初始密码: $(_yellow '123@@@') 初始端口: $(_yellow '22')"
        echo "$(_yellow '按任意键继续')"
        read -n 1 -s -r -p ""
        script_bin456789
    }

    reinstall_win_bin456789() {
        echo "重装后初始用户名: $(_yellow 'Administrator') 初始密码: $(_yellow '123@@@') 初始端口: $(_yellow '3389')"
        echo "$(_yellow '按任意键继续')"
        read -n 1 -s -r -p ""
        script_bin456789
    }

    # 重装系统
    while true; do
        need_root
        clear_screen
        echo "$(_red '注意:') 重装有风险失联, 不放心者慎用重装预计花费15分钟, 请提前备份数据!"
        echo "$(_blue '感谢MollyLau大佬和bin456789大佬的脚本支持!')"
        short_line
        echo "$(_yellow "$os_text")"
        short_line
        echo "1. Debian 12                  2. Debian 11"
        echo "3. Debian 10                  4. Debian 9"
        short_line
        echo "11. Ubuntu 24.04              12. Ubuntu 22.04"
        echo "13. Ubuntu 20.04              14. Ubuntu 18.04"
        short_line
        echo "21. Rocky Linux 9             22. Rocky Linux 8"
        echo "23. Alma Linux 9              24. Alma Linux 8"
        echo "25. Oracle Linux 9            26. Oracle Linux 8"
        echo "27. Fedora Linux 41           28. Fedora Linux 40"
        echo "29. CentOS 10                 30. CentOS 7"
        short_line
        echo "31. Alpine Linux              32. Arch Linux"
        echo "33. Kali Linux                34. openEuler"
        echo "35. openSUSE Tumbleweed       36. gentoo"
        short_line
        echo "41. Windows 11                42. Windows 10"
        echo "43. Windows 7                 44. Windows Server 2022"
        echo "45. Windows Server 2019       46. Windows Server 2016"
        echo "47. Windows 11 ARM"
        short_line
        echo "0. 返回上一级菜单"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case "$choice" in
            1)
                reinstall_linux_MollyLau
                bash InstallNET.sh -debian 12
                reboot
                exit
            ;;
            2)
                reinstall_linux_MollyLau
                bash InstallNET.sh -debian 11
                reboot
                exit
            ;;
            3)
                reinstall_linux_MollyLau
                bash InstallNET.sh -debian 10
                reboot
                exit
            ;;
            4)
                reinstall_linux_MollyLau
                bash InstallNET.sh -debian 9
                reboot
                exit
            ;;
            11)
                reinstall_linux_MollyLau
                bash InstallNET.sh -ubuntu 24.04
                reboot
                exit
            ;;
            12)
                reinstall_linux_MollyLau
                bash InstallNET.sh -ubuntu 22.04
                reboot
                exit
            ;;
            13)
                reinstall_linux_MollyLau
                bash InstallNET.sh -ubuntu 20.04
                reboot
                exit
            ;;
            14)
                reinstall_linux_MollyLau
                bash InstallNET.sh -ubuntu 18.04
                reboot
                exit
            ;;
            21)
                reinstall_linux_bin456789
                bash reinstall.sh rocky 9 --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            22)
                reinstall_linux_bin456789
                bash reinstall.sh rocky 8 --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            23)
                reinstall_linux_bin456789
                bash reinstall.sh almalinux 9 --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            24)
                reinstall_linux_bin456789
                bash reinstall.sh almalinux 8 --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            25)
                reinstall_linux_bin456789
                bash reinstall.sh oracle 9 --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            26)
                reinstall_linux_bin456789
                bash reinstall.sh oracle 8 --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            27)
                reinstall_linux_bin456789
                bash reinstall.sh fedora 41 --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            28)
                reinstall_linux_bin456789
                bash reinstall.sh fedora 40 --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            29)
                reinstall_linux_bin456789
                bash reinstall.sh centos 10 --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            30)
                reinstall_linux_MollyLau
                bash InstallNET.sh -centos 7
                reboot
                exit
            ;;
            31)
                reinstall_linux_MollyLau
                bash InstallNET.sh -alpine
                reboot
                exit
            ;;
            32)
                reinstall_linux_bin456789
                bash reinstall.sh arch --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            33)
                reinstall_linux_bin456789
                bash reinstall.sh kali --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            34)
                reinstall_linux_bin456789
                bash reinstall.sh openeuler --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            35)
                reinstall_linux_bin456789
                bash reinstall.sh opensuse --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            36)
                reinstall_linux_bin456789
                bash reinstall.sh gentoo --password 123@@@ --ssh-port 22
                reboot
                exit
            ;;
            41)
                reinstall_win_MollyLau
                bash InstallNET.sh -windows 11 -lang "cn"
                reboot
                exit
            ;;
            42)
                reinstall_win_MollyLau
                bash InstallNET.sh -windows 10 -lang "cn"
                reboot
                exit
            ;;
            43)
                reinstall_win_bin456789
                bash reinstall.sh windows --iso="https://drive.massgrave.dev/cn_windows_7_professional_with_sp1_x64_dvd_u_677031.iso" --image-name='Windows 7 PROFESSIONAL'
                reboot
                exit
            ;;
            44)
                reinstall_win_MollyLau
                bash InstallNET.sh -windows 2022 -lang "cn"
                reboot
                exit
            ;;
            45)
                reinstall_win_MollyLau
                bash InstallNET.sh -windows 2019 -lang "cn"
                reboot
                exit
            ;;
            46)
                reinstall_win_MollyLau
                bash InstallNET.sh -windows 2016 -lang "cn"
                reboot
                exit
            ;;
            47)
                reinstall_win_bin456789
                bash reinstall.sh dd --img https://r2.hotdog.eu.org/win11-arm-with-pagefile-15g.xz
                reboot
                exit
            ;;
            0)
                break
            ;;
            *)
                echo "$(_red '无效选项, 请重新输入')"
                break
            ;;
        esac
    done
}

check_swap() {
    # 获取当前总交换空间大小 (以MB为单位)
    local swap_total
    swap_total=$(free -m | awk 'NR==3{print $2}')

    # 获取当前物理内存大小（以MB为单位）
    local mem_total
    mem_total=$(free -m | awk 'NR==2{print $2}')

    # 判断是否需要创建虚拟内存
    if [ "$swap_total" -le 0 ]; then
        if [ "$mem_total" -le 900 ]; then
            # 系统没有交换空间且物理内存小于等于900MB，设置默认的1024MB交换空间
            local new_swap=1024
            add_swap "$new_swap"
        else
            _yellow "物理内存大于900MB，不需要添加交换空间"
        fi
    else
        _green "系统已经有交换空间，总大小为${swap_total}MB"
    fi
}

add_swap() {
    virt_check
    local new_swap="$1"

    # VPS虚拟化校验排除LXC和OpenVZ
    if [[ "$virt_type" =~ ^(openvz|lxc|lxd)$ ]]; then
        _err_msg "$(_red "您的VPS基于${virt_type}不受支持！")"
        end_of
        return 1
    fi

    # 获取当前系统中所有的swap分区
    local swap_partitions
    swap_partitions=$(grep -E '^/dev/' /proc/swaps | awk '{print $1}')

    # 遍历并删除所有的swap分区
    for partition in $swap_partitions; do
        swapoff "$partition"
        wipefs -a "$partition"  # 清除文件系统标识符
        mkswap -f "$partition"
    done

    # 确保/swapfile不再被使用
    swapoff /swapfile >/dev/null 2>&1

    # 删除旧的/swapfile
    [ -f /swapfile ] && rm -f /swapfile

    # 创建新的swap文件
    dd if=/dev/zero of=/swapfile bs=1M count="$new_swap" status=progress
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile

    # 更新fstab
    if ! grep -q '/swapfile' /etc/fstab; then
        echo "/swapfile swap swap defaults 0 0" | tee -a /etc/fstab
    fi

    # 针对Alpine Linux的额外设置
    if [ -f /etc/alpine-release ]; then
        echo "nohup swapon /swapfile" > /etc/local.d/swap.start
        chmod +x /etc/local.d/swap.start
        rc-update add local
    fi

    _green "虚拟内存大小已调整为: ${new_swap}MB"
}

# 查看当前服务器时区
current_timezone() {
    if grep -q 'Alpine' /etc/issue; then
        date +"%Z %z"
    else
        timedatectl | grep "Time zone" | awk '{print $3}'
    fi
}

# 设置时区
set_timedate() {
    local timezone="$1"
    if grep -q 'Alpine' /etc/issue; then
        install tzdata
        cp /usr/share/zoneinfo/"${timezone}" /etc/localtime
        hwclock --systohc
    else
        timedatectl set-timezone "${timezone}"
    fi
}

# 用于检查并设置net.core.default_qdisc参数
set_default_qdisc() {
    local qdisc_control="net.core.default_qdisc"
    # local default_qdisc="fq"
    local config_file="/etc/sysctl.conf"
    local current_value
    local choice
    local chosen_qdisc

    # 使用grep查找现有配置, 忽略等号周围的空格, 排除注释行
    if grep -q "^[^#]*${qdisc_control}\s*=" "${config_file}"; then
        # 存在该设置项，检查其值
        current_value=$(grep "^[^#]*${qdisc_control}\s*=" "${config_file}" | sed -E "s/^[^#]*${qdisc_control}\s*=\s*(.*)/\1/")
        _yellow "当前队列规则为: $current_value"
    else
        # 没有找到该设置项
        current_value=""
    fi

    # 提供用户选择菜单
    while true; do
        echo "请选择要设置的队列规则"
        short_line
        echo "1. fq (默认值): 基本的公平排队算法，旨在确保每个流获得公平的带宽分配，防止某个流占用过多带宽"
        echo "2. fq_pie      : 将FQ和PI (Proportional Integral) 控制结合在一起，旨在改善延迟和带宽利用率"
        echo "3. fq_codel    : 结合了公平排队和控制延迟的算法，通过主动丢包和公平分配带宽来减少延迟并提高多流的性能"
        short_line

        reading '请输入选项并按回车键确认 (回车使用默认值: fq): ' choice

        case $choice in
            1|"")
                chosen_qdisc="fq"
                break
                ;;
            2)
                chosen_qdisc="fq_pie"
                break
                ;;
            3)
                chosen_qdisc="fq_codel"
                break
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
    done

    # 如果当前值不等于选择的值，进行更新
    if [ "$current_value" != "$chosen_qdisc" ]; then
        if [ -z "$current_value" ]; then
            # 如果没有设置项，则新增
            echo "${qdisc_control}=${chosen_qdisc}" >> "${config_file}"
        else
            # 如果设置项存在但值不匹配，进行替换
            sed -i -E "s|^[^#]*${qdisc_control}\s*=\s*.*|${qdisc_control}=${chosen_qdisc}|" "${config_file}"
        fi
        sysctl -p
        _green "队列规则已设置为: $chosen_qdisc"
    else
        _yellow "队列规则已经是 $current_value，无需更改"
    fi
}

bbr_on() {
    local congestion_control="net.ipv4.tcp_congestion_control"
    local config_file="/etc/sysctl.conf"
    local current_value

    current_value=$(awk -F '=' -v key="$congestion_control" '!/^#/ && $1 ~ key {gsub(/ /, "", $2); print $2}' "${config_file}")

    if [ "$current_value" == "bbr" ]; then
        return
    elif [ -n "$current_value" ]; then
        sed -i -E "s|^[^#]*${congestion_control}\s*=\s*.*|${congestion_control}=bbr|" "${config_file}"
    else
        echo "${congestion_control}=bbr" >> "${config_file}"
    fi

    sysctl -p
    current_value=$(sysctl -n "${congestion_control}")
    [ "$current_value" != "bbr" ] && return 1
}

xanmod_bbr3() {
    local choice kernel_version arch
    need_root

    echo "XanMod BBR3管理"
    if dpkg -l | grep -q 'linux-xanmod'; then
        while true; do
            clear_screen
            echo "已安装XanMod的BBRv3内核"
            echo "当前内核版本: $(uname -r)"
            echo ""
            echo "内核管理"
            short_line
            echo "1. 更新BBRv3内核              2. 卸载BBRv3内核"
            short_line
            echo "0. 返回上一级选单"
            short_line

            reading '请输入选项并按回车键确认: ' choice

            case "$choice" in
                1)
                    pkg_uninstall 'linux-*xanmod1*'
                    update-grub
                    # wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
                    wget -qO - "${github_Proxy}https://raw.githubusercontent.com/honeok/Tools/master/archive.key" | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes

                    # 添加存储库
                    echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list

                    # kernel_version=$(wget -q https://dl.xanmod.org/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | sed -n 's/.*x86-64-v\([0-9]\+\).*/\1/p')
                    kernel_version=$(curl -fskL -O "${github_Proxy}https://raw.githubusercontent.com/honeok/Tools/master/check_x86-64_psabi.sh" && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | awk -F 'x86-64-v' '{print $2}')

                    pkg_install linux-xanmod-x64v"$kernel_version"

                    echo "$(_green 'XanMod内核已更新, 重启后生效')"
                    [ -f "/etc/apt/sources.list.d/xanmod-release.list" ] && rm -f /etc/apt/sources.list.d/xanmod-release.list
                    [ -f "check_x86-64_psabi.sh" ] && rm -f "check_x86-64_psabi.sh"

                    server_reboot
                ;;
                2)
                    pkg_uninstall 'linux-*xanmod1*'
                    update-grub
                    echo "$(_green 'XanMod内核已卸载, 重启后生效')"
                    server_reboot
                ;;
                0)
                    break
                ;;
                *)
                    echo "$(_red '无效选项, 请重新输入')"
                ;;
            esac
        done
    else
        # 未安装则安装
        clear_screen
        echo "请备份数据, 将为你升级Linux内核开启XanMod BBR3"
        long_line
        echo "仅支持Debian/Ubuntu系统, 且仅限x86_64架构!"
        echo "请备份数据, 将为你升级Linux内核开启BBR3!"
        echo "如果VPS内存仅有512M内存, 请提前添加1G交换内存, 防止因内存不足失联!"
        long_line

        reading '确定继续吗? (y/n): ' choice

        case "$choice" in
            [Yy])
                if [ "$os_name" != 'debian' ] && [ "$os_name" != 'ubuntu' ]; then
                    echo "$(_red '当前环境不支持, 仅支持Debian和Ubuntu系统.')"
                    end_of
                    linux_system_tools
                fi

                # 检查系统架构
                if [ "$(dpkg --print-architecture)" != "amd64" ]; then
                    echo "$(_red '当前环境不支持, 仅支持x86_64架构.')"
                    end_of
                    linux_system_tools
                fi

                check_swap
                for pkg in "wget" "gnupg"; do
                    if ! _exists "$pkg" >/dev/null 2>&1; then
                        pkg_install "$pkg"
                    fi
                done

                # wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
                wget -qO - "${github_Proxy}https://raw.githubusercontent.com/honeok/Tools/master/archive.key" | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes

                # 添加存储库
                echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list

                # kernel_version=$(wget -q https://dl.xanmod.org/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | sed -n 's/.*x86-64-v\([0-9]\+\).*/\1/p')
                kernel_version=$(curl -fskL -O "${github_Proxy}https://raw.githubusercontent.com/honeok/Tools/master/check_x86-64_psabi.sh" && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | awk -F 'x86-64-v' '{print $2}')

                pkg_install linux-xanmod-x64v"$kernel_version"

                set_default_qdisc
                bbr_on

                echo "$(_green 'XanMod内核安装并启用BBR3成功, 重启后生效!')"
                [ -f "/etc/apt/sources.list.d/xanmod-release.list" ] && rm -f /etc/apt/sources.list.d/xanmod-release.list
                [ -f "check_x86-64_psabi.sh" ] && rm -f "check_x86-64_psabi.sh"

                server_reboot
            ;;
            [Nn])
                :
                echo "$(_yellow '已取消')"
            ;;
            *)
                echo "$(_red '无效选项, 请重新输入')"
            ;;
        esac
    fi
}

linux_mirror() {
    local choice
    need_root

    while true; do
        clear_screen
        echo "选择更新源区域"
        echo "接入LinuxMirrors切换系统更新源"
        short_line
        echo "1. 中国大陆【默认】          2. 中国大陆【教育网】          3. 海外地区"
        short_line
        echo "0. 返回上一级"
        short_line
    
        reading '请输入选项并按回车键确认: ' choice
    
        case $choice in
            1)
                bash <(curl -sSL https://linuxmirrors.cn/main.sh)
                ;;
            2)
                bash <(curl -sSL https://linuxmirrors.cn/main.sh) --edu
                ;;
            3)
                bash <(curl -sSL https://linuxmirrors.cn/main.sh) --abroad
                ;;
            0)
                break
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
    done
}

check_crontab_installed() {
    if command -v crontab >/dev/null 2>&1; then
        _green "crontab已安装！"
        return $?
    else
        install_crontab
        return 0
    fi
}

install_crontab() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|kali)
                apt update
                apt install -y cron
                enable cron
                start cron
                ;;
            centos|rhel|almalinux|rocky|fedora)
                yum install -y cronie
                enable crond
                start crond
                ;;
            alpine)
                apk add --no-cache cronie
                rc-update add crond
                rc-service crond start
                ;;
            arch|manjaro)
                pacman -S --noconfirm cronie
                enable cronie
                start cronie
                ;;
            opensuse|suse|opensuse-tumbleweed)
                zypper install -y cron
                enable cron
                start cron
                ;;
            openwrt|lede)
                opkg update
                opkg install cron
                /etc/init.d/cron enable
                /etc/init.d/cron start
                ;;
            *)
                _red "不支持的发行版:$ID"
                return 1
                ;;
        esac
    else
        _red "无法确定操作系统"
        return 1
    fi

    _yellow "Crontab已安装且Cron服务正在运行"
}

new_ssh_port() {
    # 备份SSH配置文件,如果备份文件不存在,只取原始配置文件
    backup_file="/etc/ssh/sshd_config.bak"
    if [[ ! -f $backup_file ]]; then
        cp /etc/ssh/sshd_config $backup_file
    fi

    # 检查是否有未被注释的Port行
    existing_port=$(grep -E '^[^#]*Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')

    if [[ -z $existing_port ]]; then
        # 如果没有启用的Port行,则取消注释并设置新端口
        sed -i 's/^\s*#\s*Port/Port/' /etc/ssh/sshd_config
        sed -i "s/^\s*Port [0-9]\+/Port $new_port/" /etc/ssh/sshd_config
    else
        # 如果已经有启用的Port行,则只更新端口号
        sed -i "s/^\s*Port [0-9]\+/Port $new_port/" /etc/ssh/sshd_config
    fi

    # 清理不再使用的配置文件
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        rm -f /etc/ssh/sshd_config.d/*
    fi
    if [[ -d /etc/ssh/ssh_config.d ]]; then
        rm -f /etc/ssh/ssh_config.d/*
    fi

    # 重启SSH服务
    restart_ssh

    iptables_open
    remove iptables-persistent ufw firewalld iptables-services >/dev/null 2>&1

    _green "SSH端口已修改为:$new_port"
    sleep 1
}

cron_manager() {
    local choice newquest dingshi day weekday hour minute kquest

    while true; do
        clear_screen
        check_crontab_installed
        clear_screen
        echo "定时任务列表"
        short_line
        crontab -l
        short_line
        echo "操作"
        short_line
        echo "1. 添加定时任务              2. 删除定时任务"
        echo "3. 编辑定时任务              4. 删除所有定时任务"
        short_line
        echo "0. 返回上一级选单"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1)
                echo -n -e "${yellow}请输入新任务的执行命令: ${white}"
                read -r newquest
                short_line
                echo "1. 每月任务                 2. 每周任务"
                echo "3. 每天任务                 4. 每小时任务"
                short_line

                reading '请输入选项并按回车键确认: ' dingshi

                case $dingshi in
                    1)
                        echo -n -e "${yellow}选择每月的几号执行任务? (1-30): ${white}"
                        read -r day
                        if [[ ! $day =~ ^[1-9]$|^[12][0-9]$|^30$ ]]; then
                            _red "无效的日期输入"
                            continue
                        fi
                        if ! (crontab -l ; echo "0 0 $day * * $newquest") | crontab - >/dev/null 2>&1; then
                            _red "添加定时任务失败"
                        fi
                        ;;
                    2)
                        echo -n -e "${yellow}选择周几执行任务? (0-6，0代表星期日): ${white}"
                        read -r weekday
                        if [[ ! $weekday =~ ^[0-6]$ ]]; then
                            _red "无效的星期输入"
                            continue
                        fi
                        if ! (crontab -l ; echo "0 0 * * $weekday $newquest") | crontab - >/dev/null 2>&1; then
                            _red "添加定时任务失败"
                        fi
                        ;;
                    3)
                        echo -n -e "${yellow}选择每天几点执行任务? (小时，0-23): ${white}"
                        read -r hour
                        if [[ ! $hour =~ ^[0-9]$|^[1][0-9]$|^[2][0-3]$ ]]; then
                            _red "无效的小时输入"
                            continue
                        fi
                        if ! (crontab -l ; echo "0 $hour * * * $newquest") | crontab - >/dev/null 2>&1; then
                            _red "添加定时任务失败"
                        fi
                        ;;
                    4)
                        echo -n -e "${yellow}输入每小时的第几分钟执行任务? (分钟,0-60): ${white}"
                        read -r minute
                        if [[ ! $minute =~ ^[0-5][0-9]$ ]]; then
                            _red "无效的分钟输入"
                            continue
                        fi
                        if ! (crontab -l ; echo "$minute * * * * $newquest") | crontab - >/dev/null 2>&1; then
                            _red "添加定时任务失败"
                        fi
                        ;;
                    *)
                        break  # 跳出
                        ;;
                esac
                ;;
            2)
                echo -n -e "${yellow}请输入需要删除任务的关键字: ${white}"
                read -r kquest
                if crontab -l | grep -v "$kquest" | crontab -; then
                    _green "$kquest 定时任务已删除"
                else
                    _red "删除定时任务失败"
                fi
                ;;
            3)
                crontab -e
                ;;
            4)
                if crontab -r >/dev/null; then
                    _green "所有定时任务已删除"
                else
                    _red "删除所有定时任务失败"
                fi
                ;;
            0)
                break  # 跳出循环,退出菜单
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
    done
}

network_usage_status() {
    network_usage_summary=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
        NR > 2 { rx_total += $2; tx_total += $10 }
        END {
            rx_units = "Bytes";
            tx_units = "Bytes";
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "KB"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "MB"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "GB"; }

            if (tx_total > 1024) { tx_total /= 1024; tx_units = "KB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "MB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "GB"; }

            printf("总接收: %.2f %s\n总发送: %.2f %s\n", rx_total, rx_units, tx_total, tx_units);
        }' /proc/net/dev)
}

add_sshkey() {
    # 生成 ED25519 类型的 SSH 密钥
    # ssh-keygen -t rsa -b 4096 -C "xxxx@email.com" -f /root/.ssh/sshkey -N ""
    ssh-keygen -t ed25519 -C "xxxx@email.com" -f /root/.ssh/sshkey -N ""

    # 将公钥添加到 authorized_keys 文件中
    cat ~/.ssh/sshkey.pub >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys

    # 获取 IP 地址
    ip_address
    echo -e "私钥信息已生成务必复制保存，可保存为${yellow}${ipv4_address}_ssh.key${white}文件，用于以后的SSH登录"
    short_line
    cat ~/.ssh/sshkey
    short_line

    # 修改 sshd 配置，禁止密码登录，仅允许公钥登录
    sed -i -e 's/^\s*#\?\s*PermitRootLogin .*/PermitRootLogin prohibit-password/' \
           -e 's/^\s*#\?\s*PasswordAuthentication .*/PasswordAuthentication no/' \
           -e 's/^\s*#\?\s*PubkeyAuthentication .*/PubkeyAuthentication yes/' \
           -e 's/^\s*#\?\s*ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config

    # 删除 sshd 和 ssh 配置文件中的无用文件夹
    rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*

    _red "root私钥登录已开启，已关闭root密码登录重连将会生效"
}

telegram_bot() {
    need_root
    set_script_dir

    local choice TG_check_notify TG_SSH_check_notify
    local TG_check_notify_hash="1a5694045098d5ceed3ab6d9b2827dea9677a0a6aa9cade357dec4a2bc514444"
    local TG_SSH_check_notify_hash="61813dc31c2a3d335924a5d24bf212350848dc748c4811e362c06a9b313167c1"

    echo "TG-bot监控预警功能"
    short_line
    echo "您需要配置TG机器人API和接收预警的用户ID，即可实现本机CPU/内存/硬盘/流量/SSH登录的实时监控预警"
    echo "到达阈值后会向用户发预警消息，流量重启服务器将重新计算"
    short_line
                
    echo -n -e "${yellow}确定继续吗? (y/n): ${white}"
    read -r choice

    case $choice in
        [Yy])
            install tmux bc jq
            check_crontab_installed

            if [ -f "${global_script_dir}/TG-check-notify.sh" ]; then
                chmod +x "${global_script_dir}/TG-check-notify.sh"
                vim "${global_script_dir}/TG-check-notify.sh"
            else
                curl -fsL -o "${global_script_dir}/TG-check-notify.sh" "${github_Proxy}https://raw.githubusercontent.com/honeok/Tools/master/TG-check-notify.sh"
                # 计算文件哈希
                TG_check_notify=$(sha256sum "${global_script_dir}/TG-check-notify.sh" | awk '{ print $1 }')

                # 校验哈希值
                if [ "$TG_check_notify" != "$TG_check_notify_hash" ]; then
                    _red "文件哈希校验失败，脚本可能被篡改"
                    sleep 1
                    rm -f "${global_script_dir}/TG-check-notify.sh"
                    linux_system_tools # 返回系统工具菜单
                else
                    chmod +x "${global_script_dir}/TG-check-notify.sh"
                    vim "${global_script_dir}/TG-check-notify.sh"
                fi
            fi

            tmux kill-session -t TG-check-notify >/dev/null 2>&1
            tmux new -d -s TG-check-notify "${global_script_dir}/TG-check-notify.sh"
            crontab -l | grep -v "${global_script_dir}/TG-check-notify.sh" | crontab - >/dev/null 2>&1
            (crontab -l ; echo "@reboot tmux new -d -s TG-check-notify '${global_script_dir}/TG-check-notify.sh'") | crontab - >/dev/null 2>&1

            curl -fsL -o "${global_script_dir}/TG-SSH-check-notify.sh" "${github_Proxy}https://raw.githubusercontent.com/honeok/Tools/master/TG-SSH-check-notify.sh"
            # 计算文件哈希
            TG_SSH_check_notify=$(sha256sum "${global_script_dir}/TG-SSH-check-notify.sh" | awk '{ print $1 }')

            # 校验哈希值
            if [ "$TG_SSH_check_notify" != "$TG_SSH_check_notify_hash" ]; then
                _red "文件哈希校验失败,脚本可能被篡改"
                sleep 1
                rm -f "${global_script_dir}/TG-SSH-check-notify.sh"
                linux_system_tools # 返回系统工具菜单
            else
                sed -i "3i$(grep '^TELEGRAM_BOT_TOKEN=' "${global_script_dir}/TG-check-notify.sh")" "${global_script_dir}/TG-SSH-check-notify.sh"
                sed -i "4i$(grep '^CHAT_ID=' "${global_script_dir}/TG-check-notify.sh")" "${global_script_dir}/TG-SSH-check-notify.sh"
                chmod +x "${global_script_dir}/TG-SSH-check-notify.sh"
            fi

            # 添加到~/.profile文件中
            if ! grep -q "bash ${global_script_dir}/TG-SSH-check-notify.sh" ~/.profile >/dev/null 2>&1; then
                echo "bash ${global_script_dir}/TG-SSH-check-notify.sh" >> ~/.profile
                if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
                    echo 'source ~/.profile' >> ~/.bashrc
                fi
            fi

            source "$HOME/.profile"

            clear_screen
            _green "TG-bot预警系统已启动"
            _yellow "你还可以将${global_script_dir}目录中的TG-check-notify.sh预警文件放到其他机器上直接使用！"
            ;;
        [Nn])
            _yellow "已取消"
            ;;
        *)
            _red "无效选项，请重新输入"
            ;;
    esac
}

redhat_kernel_update() {
    install_elrepo() {
        # 导入ELRepo GPG公钥
        _yellow "导入ELRepo GPG 公钥"
        rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
        # 检测系统版本
        local os_version os_name
        os_version=$(rpm -q --qf "%{VERSION}" "$(rpm -qf /etc/*release)" 2>/dev/null | awk -F '.' '{print $1}')
        os_name=$(grep "^ID=" /etc/*release | awk -F'=' '{print $2}' | sed 's/"//g')
        # 确保支持的操作系统上运行
        if [[ "$os_name" != "rhel" && "$os_name" != "centos" && "$os_name" != "rocky" && "$os_name" != "almalinux" && "$os_name" != "oracle" && "$os_name" != "amazon" ]]; then
            _red "不支持的操作系统: $os_name"
            end_of
            linux_system_tools
        fi

        # 打印检测到的操作系统信息
        _yellow "检测到的操作系统: $os_name $os_version"

        # 根据系统版本安装对应的 ELRepo 仓库配置
        if [[ "$os_version" == 8 ]]; then
            _yellow "安装ELRepo仓库配置(版本 8)"
            yum install https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm -y
        elif [[ "$os_version" == 9 ]]; then
            _yellow "安装ELRepo仓库配置(版本 9)"
            yum install https://www.elrepo.org/elrepo-release-9.el9.elrepo.noarch.rpm -y
        else
            _red "不支持的系统版本:$os_version"
            end_of
            linux_system_tools
        fi

        # 启用ELRepo内核仓库并安装最新的主线内核
        _yellow "启用ELRepo内核仓库并安装最新的主线内核"
        yum -y --enablerepo=elrepo-kernel install kernel-ml
        _yellow "已安装ELRepo仓库配置并更新到最新主线内核"
        server_reboot
    }

    need_root

    if uname -r | grep -q 'elrepo'; then
        while true; do
            clear_screen
            kernel_version=$(uname -r)
            echo "您已安装elrepo内核"
            echo "当前内核版本: $kernel_version"

            echo ""
            echo "内核管理"
            short_line
            echo "1. 更新elrepo内核     2. 卸载elrepo内核"
            short_line
            echo "0. 返回上一级选单"
            short_line

            reading '请输入选项并按回车键确认: ' choice

            case $choice in
                1)
                    dnf remove -y elrepo-release
                    rpm -qa | grep elrepo | grep kernel | xargs rpm -e --nodeps
                    install_elrepo
                    server_reboot
                    ;;
                2)
                    dnf remove -y elrepo-release
                    rpm -qa | grep elrepo | grep kernel | xargs rpm -e --nodeps
                    _green "elrepo内核已卸载，重启后生效"
                    server_reboot
                    ;;
                3)
                    break
                    ;;
                0)
                    _red "无效选项，请重新输入"
                    ;;
            esac
        done
    else
        clear_screen
        _yellow "请备份数据，将为你升级Linux内核"
        long_line
        echo "仅支持红帽系列发行版RedHat/CentOS/Rocky/Almalinux/Oracle/Amazon"
        echo "升级Linux内核可提升系统性能和安全，建议有条件的尝试，生产环境谨慎升级！"
        long_line

        echo -n -e "${yellow}确定继续吗? (y/n): ${white}"
        read -r choice

        case $choice in
            [Yy])
                check_swap
                install_elrepo
                server_reboot
                ;;
            [Nn])
                echo "已取消"
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
    fi
}

# 高性能模式优化函数
optimize_high_performance() {
    echo -e "${yellow}切换到${optimization_mode}${white}"

    echo -e "${yellow}优化文件描述符${white}"
    ulimit -n 65535

    echo -e "${yellow}优化虚拟内存${white}"
    sysctl -w vm.swappiness=10 2>/dev/null
    sysctl -w vm.dirty_ratio=15 2>/dev/null
    sysctl -w vm.dirty_background_ratio=5 2>/dev/null
    sysctl -w vm.overcommit_memory=1 2>/dev/null
    sysctl -w vm.min_free_kbytes=65536 2>/dev/null

    echo -e "${yellow}优化网络设置${white}"
    sysctl -w net.core.rmem_max=16777216 2>/dev/null
    sysctl -w net.core.wmem_max=16777216 2>/dev/null
    sysctl -w net.core.netdev_max_backlog=250000 2>/dev/null
    sysctl -w net.core.somaxconn=4096 2>/dev/null
    sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216' 2>/dev/null
    sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216' 2>/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
    sysctl -w net.ipv4.tcp_max_syn_backlog=8192 2>/dev/null
    sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null
    sysctl -w net.ipv4.ip_local_port_range='1024 65535' 2>/dev/null

    echo -e "${yellow}优化缓存管理${white}"
    sysctl -w vm.vfs_cache_pressure=50 2>/dev/null

    echo -e "${yellow}优化CPU设置${white}"
    sysctl -w kernel.sched_autogroup_enabled=0 2>/dev/null

    echo -e "${yellow}其他优化${white}"
    # 禁用透明大页面,减少延迟
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
    # 禁用NUMA balancing
    sysctl -w kernel.numa_balancing=0 2>/dev/null
}

# 均衡模式优化函数
optimize_balanced() {
    echo -e "${yellow}切换到均衡模式${white}"

    echo -e "${yellow}优化文件描述符${white}"
    ulimit -n 32768

    echo -e "${yellow}优化虚拟内存${white}"
    sysctl -w vm.swappiness=30 2>/dev/null
    sysctl -w vm.dirty_ratio=20 2>/dev/null
    sysctl -w vm.dirty_background_ratio=10 2>/dev/null
    sysctl -w vm.overcommit_memory=0 2>/dev/null
    sysctl -w vm.min_free_kbytes=32768 2>/dev/null

    echo -e "${yellow}优化网络设置${white}"
    sysctl -w net.core.rmem_max=8388608 2>/dev/null
    sysctl -w net.core.wmem_max=8388608 2>/dev/null
    sysctl -w net.core.netdev_max_backlog=125000 2>/dev/null
    sysctl -w net.core.somaxconn=2048 2>/dev/null
    sysctl -w net.ipv4.tcp_rmem='4096 87380 8388608' 2>/dev/null
    sysctl -w net.ipv4.tcp_wmem='4096 32768 8388608' 2>/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
    sysctl -w net.ipv4.tcp_max_syn_backlog=4096 2>/dev/null
    sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null
    sysctl -w net.ipv4.ip_local_port_range='1024 49151' 2>/dev/null

    echo -e "${yellow}优化缓存管理${white}"
    sysctl -w vm.vfs_cache_pressure=75 2>/dev/null

    echo -e "${yellow}优化CPU设置${white}"
    sysctl -w kernel.sched_autogroup_enabled=1 2>/dev/null

    echo -e "${yellow}其他优化${white}"
    # 还原透明大页面
    echo always > /sys/kernel/mm/transparent_hugepage/enabled
    # 还原NUMA balancing
    sysctl -w kernel.numa_balancing=1 2>/dev/null
}

# 网站搭建优化函数
optimize_webserver() {
	echo -e "${yellow}切换到网站搭建优化模式${white}"

	echo -e "${yellow}优化文件描述符${white}"
	ulimit -n 65535

	echo -e "${yellow}优化虚拟内存${white}"
	sysctl -w vm.swappiness=10 2>/dev/null
	sysctl -w vm.dirty_ratio=20 2>/dev/null
	sysctl -w vm.dirty_background_ratio=10 2>/dev/null
	sysctl -w vm.overcommit_memory=1 2>/dev/null
	sysctl -w vm.min_free_kbytes=65536 2>/dev/null

	echo -e "${yellow}优化网络设置${white}"
	sysctl -w net.core.rmem_max=16777216 2>/dev/null
	sysctl -w net.core.wmem_max=16777216 2>/dev/null
	sysctl -w net.core.netdev_max_backlog=5000 2>/dev/null
	sysctl -w net.core.somaxconn=4096 2>/dev/null
	sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216' 2>/dev/null
	sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216' 2>/dev/null
	sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
	sysctl -w net.ipv4.tcp_max_syn_backlog=8192 2>/dev/null
	sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null
	sysctl -w net.ipv4.ip_local_port_range='1024 65535' 2>/dev/null

	echo -e "${yellow}优化缓存管理${white}"
	sysctl -w vm.vfs_cache_pressure=50 2>/dev/null

	echo -e "${yellow}优化CPU设置${white}"
	sysctl -w kernel.sched_autogroup_enabled=0 2>/dev/null

	echo -e "${yellow}其他优化${white}"
	# 禁用透明大页面，减少延迟
	echo never > /sys/kernel/mm/transparent_hugepage/enabled
	# 禁用 NUMA balancing
	sysctl -w kernel.numa_balancing=0 2>/dev/null
}

# 还原默认设置函数
restore_defaults() {
    echo -e "${yellow}还原到默认设置${white}"

    echo -e "${yellow}还原文件描述符${white}"
    ulimit -n 1024

    echo -e "${yellow}还原虚拟内存${white}"
    sysctl -w vm.swappiness=60 2>/dev/null
    sysctl -w vm.dirty_ratio=20 2>/dev/null
    sysctl -w vm.dirty_background_ratio=10 2>/dev/null
    sysctl -w vm.overcommit_memory=0 2>/dev/null
    sysctl -w vm.min_free_kbytes=16384 2>/dev/null

    echo -e "${yellow}还原网络设置${white}"
    sysctl -w net.core.rmem_max=212992 2>/dev/null
    sysctl -w net.core.wmem_max=212992 2>/dev/null
    sysctl -w net.core.netdev_max_backlog=1000 2>/dev/null
    sysctl -w net.core.somaxconn=128 2>/dev/null
    sysctl -w net.ipv4.tcp_rmem='4096 87380 6291456' 2>/dev/null
    sysctl -w net.ipv4.tcp_wmem='4096 16384 4194304' 2>/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=cubic 2>/dev/null
    sysctl -w net.ipv4.tcp_max_syn_backlog=2048 2>/dev/null
    sysctl -w net.ipv4.tcp_tw_reuse=0 2>/dev/null
    sysctl -w net.ipv4.ip_local_port_range='32768 60999' 2>/dev/null

    echo -e "${yellow}还原缓存管理${white}"
    sysctl -w vm.vfs_cache_pressure=100 2>/dev/null

    echo -e "${yellow}还原CPU设置${white}"
    sysctl -w kernel.sched_autogroup_enabled=1 2>/dev/null

    echo -e "${yellow}还原其他优化${white}"
    # 还原透明大页面
    echo always > /sys/kernel/mm/transparent_hugepage/enabled
    # 还原 NUMA balancing
    sysctl -w kernel.numa_balancing=1 2>/dev/null
}

clamav_freshclam() {
    _yellow "正在更新病毒库"
    docker run --rm \
        --name clamav \
        --mount source=clam_db,target=/var/lib/clamav \
        clamav/clamav-debian:latest \
        freshclam
}

clamav_scan() {
    local clamav_dir="/data/docker_data/clamav"

    if [ $# -eq 0 ]; then
        _red "请指定要扫描的目录"
        return 1
    fi

    echo -e "${yellow}正在扫描目录$* ${white}"

    # 构建mount参数
    local mount_params=""
    for dir in "$@"; do
        mount_params+="--mount type=bind,source=${dir},target=/mnt/host${dir} "
    done

    # 构建clamscan命令参数
    scan_params=""
    for dir in "$@"; do
        scan_params+="/mnt/host${dir} "
    done

    mkdir -p $clamav_dir/log/ >/dev/null 2>&1
    true > "$clamav_dir/log/scan.log" 2>/dev/null

    # 执行docker命令
    docker run -it --rm \
        --name clamav \
        --mount source=clam_db,target=/var/lib/clamav \
        "$mount_params" \
        -v $clamav_dir/log/:/var/log/clamav/ \
        clamav/clamav-debian:latest \
        clamscan -r --log=/var/log/clamav/scan.log "$scan_params"

    echo -e "${green}$* 扫描完成 病毒报告存放在${white}$clamav_dir/log/scan.log"
    _yellow "如果有病毒请在scan.log中搜索FOUND关键字确认病毒位置"
}

clamav_antivirus() {
    need_root
    while true; do
        clear_screen
        echo "clamav病毒扫描工具"
        short_line
        echo "clamav是一个开源的防病毒软件工具，主要用于检测和删除各种类型的恶意软件"
        echo "包括病毒,特洛伊木马,间谍软件，恶意脚本和其他有害软件"
        short_line
        echo "1. 全盘扫描     2. 重要目录扫描     3. 自定义目录扫描"
        short_line
        echo "0. 返回上一级选单"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1)
                install_docker
                docker volume create clam_db >/dev/null 2>&1
                clamav_freshclam
                clamav_scan /
                docker volume rm clam_db >/dev/null 2>&1
                end_of
                ;;
            2)
                install_docker
                docker volume create clam_db >/dev/null 2>&1
                clamav_freshclam
                clamav_scan /etc /var /usr /home /root
                docker volume rm clam_db >/dev/null 2>&1
                end_of
                ;;
            3)
                echo -n "请输入要扫描的目录，用空格分隔(例如: /etc /var /usr /home /root): "
                read -r directories

                install_docker
                clamav_freshclam
                clamav_scan "$directories"
                docker volume rm clam_db >/dev/null 2>&1
                end_of
                ;;
            *)
                break
                ;;
        esac
    done
}

file_manage() {
    need_root
    while true; do
        clear_screen
        echo "文件管理器"
        short_line
        echo "当前路径"
        dirname "$(realpath "$0")"
        short_line
        ls --color=auto -x
        short_line
        echo "1.  进入目录           2.  创建目录             3.  修改目录权限         4.  重命名目录"
        echo "5.  删除目录           6.  返回上一级目录"
        short_line
        echo "11. 创建文件           12. 编辑文件             13. 修改文件权限         14. 重命名文件"
        echo "15. 删除文件"
        short_line
        echo "21. 压缩文件目录       22. 解压文件目录         23. 移动文件目录         24. 复制文件目录"
        echo "25. 传文件至其他服务器"
        short_line
        echo "0.  返回上一级"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1)
                # 进入目录
                echo -n "请输入目录名: "
                read -r dirname
                cd "$dirname" 2>/dev/null || _red "无法进入目录"
                ;;
            2)
                # 创建目录
                echo -n "请输入要创建的目录名: "
                read -r dirname
                if mkdir -p "$dirname"; then
                    _green "目录已创建"
                else
                    _red "创建失败"
                fi
                ;;
            3)
                # 修改目录权限
                echo -n "请输入目录名: "
                read -r dirname
                echo -n "请输入权限(如755): "
                read -r perm
                if chmod "$perm" "$dirname"; then
                    _green "权限已修改"
                else
                    _red "修改失败"
                fi
                ;;
            4)
                # 重命名目录
                echo -n "请输入当前目录名: "
                read -r current_name
                echo -n "请输入新目录名: "
                read -r new_name
                if mv "$current_name" "$new_name"; then
                    _green "目录已重命名"
                else
                    _red "重命名失败"
                fi
                ;;
            5)
                # 删除目录
                echo -n "请输入要删除的目录名: "
                read -r dirname
                if rm -rf "$dirname"; then
                    _green "目录已删除"
                else
                    _red "删除失败"
                fi
                ;;
            6)
                # 返回上一级目录
                cd ..
                ;;
            11)
                # 创建文件
                echo -n "请输入要创建的文件名: "
                read -r filename
                if touch "$filename"; then
                    _green "文件已创建"
                else
                    _red "创建失败"
                fi
                ;;
            12)
                # 编辑文件
                echo -n "请输入要编辑的文件名: "
                read -r filename
                install vim
                vim "$filename"
                ;;
            13)
                # 修改文件权限
                echo -n "请输入文件名: "
                read -r filename
                echo -n "请输入权限(如 755): "
                read -r perm
                if chmod "$perm" "$filename"; then
                    _green "权限已修改"
                else
                    _red "修改失败"
                fi
                ;;
            14)
                # 重命名文件
                echo -n "请输入当前文件名: "
                read -r current_name
                echo -n "请输入新文件名: "
                read -r new_name
                if mv "$current_name" "$new_name"; then
                    _green "文件已重命名"
                else
                    _red "重命名失败"
                fi
                ;;
            15)
                # 删除文件
                echo -n "请输入要删除的文件名: "
                read -r filename
                if rm -f "$filename"; then
                    _green "文件已删除"
                else
                    _red "删除失败"
                fi
                ;;
            21)
                # 压缩文件/目录
                echo -n "请输入要压缩的文件/目录名: "
                read -r name
                install tar
                if tar -czvf "$name.tar.gz" "$name"; then
                    _green "已压缩为 $name.tar.gz"
                else
                    _red "压缩失败"
                fi
                ;;
            22)
                # 解压文件/目录
                echo -n "请输入要解压的文件名(.tar.gz): "
                read -r filename
                install tar
                if tar -xzvf "$filename"; then
                    _green "已解压 $filename"
                else
                    _red "解压失败"
                fi
                ;;
            23)
                # 移动文件或目录
                echo -n "请输入要移动的文件或目录路径: "
                read -r src_path
                if [ ! -e "$src_path" ]; then
                    _red "错误: 文件或目录不存在"
                    continue
                fi

                echo -n "请输入目标路径(包括新文件名或目录名): "
                read -r dest_path
                if [ -z "$dest_path" ]; then
                    _red "错误: 请输入目标路径"
                    continue
                fi

                if mv "$src_path" "$dest_path"; then
                    _green "文件或目录已移动到 $dest_path"
                else
                    _red "移动文件或目录失败"
                fi
                ;;
            24)
                # 复制文件目录
                echo -n "请输入要复制的文件或目录路径: "
                read -r src_path
                if [ ! -e "$src_path" ]; then
                    _red "错误: 文件或目录不存在"
                    continue
                fi

                echo -n "请输入目标路径(包括新文件名或目录名): "
                read -r dest_path
                if [ -z "$dest_path" ]; then
                    _red "错误: 请输入目标路径"
                    continue
                fi

                # 使用 -r 选项以递归方式复制目录
                if cp -r "$src_path" "$dest_path"; then
                    _green "文件或目录已复制到 $dest_path"
                else
                    _red "复制文件或目录失败"
                fi
                ;;
            25)
                # 传送文件至远端服务器
                echo -n "请输入要传送的文件路径: "
                read -r file_to_transfer
                if [ ! -f "$file_to_transfer" ]; then
                    _red "错误: 文件不存在"
                    continue
                fi

                echo -n "请输入远端服务器IP: "
                read -r remote_ip
                if [ -z "$remote_ip" ]; then
                    _red "错误: 请输入远端服务器IP"
                    continue
                fi

                echo -n "请输入远端服务器用户名(默认root): "
                read -r remote_user
                
                remote_user=${remote_user:-root}

                echo -n "请输入远端服务器密码: "
                read -r -s remote_password
                if [ -z "$remote_password" ]; then
                    _red "错误: 请输入远端服务器密码"
                    continue
                fi

                echo -n "请输入登录端口(默认22): "
                read -r remote_port
                remote_port=${remote_port:-22}

                # 清除已知主机的旧条目
                ssh-keygen -f "/root/.ssh/known_hosts" -R "$remote_ip"
                sleep 2

                # 使用scp传输文件
                if scp -P "$remote_port" -o StrictHostKeyChecking=no "$file_to_transfer" "$remote_user@$remote_ip:/opt/" <<EOF
$remote_password
EOF
                then
                    _green "文件已传送至远程服务器/opt目录"
                else
                    _red "文件传送失败"
                fi

                end_of
                ;;
            0)
                break
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
    done
}

linux_language() {
    update_locale() {
        local lang=$1
        local locale_file=$2

        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case $ID in
                debian|ubuntu|kali)
                    install locales
                    sed -i "s/^\s*#\?\s*${locale_file}/${locale_file}/" /etc/locale.gen
                    locale-gen
                    echo "LANG=${lang}" > /etc/default/locale
                    export LANG=${lang}
                    echo -e "${green}系统语言已经修改为: $lang 重新连接SSH生效${white}"
                    end_of
                    ;;
                centos|rhel|almalinux|rocky|fedora)
                    install glibc-langpack-zh
                    localectl set-locale LANG="${lang}"
                    echo "LANG=${lang}" | tee /etc/locale.conf
                    echo -e "${green}系统语言已经修改为: $lang 重新连接SSH生效${white}"
                    end_of
                    ;;
                *)
                    _red "不支持的系统: $ID"
                    end_of
                    ;;
            esac
        else
            _red "不支持的系统，无法识别系统类型"
            end_of
        fi
    }

    need_root
    while true; do
        echo "当前系统语言: $LANG"
        short_line
        echo "1. 英文          2. 简体中文          3. 繁体中文"
        short_line
        echo "0. 返回上一级"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1)
                update_locale "en_US.UTF-8" "en_US.UTF-8"
                ;;
            2)
                update_locale "zh_CN.UTF-8" "zh_CN.UTF-8"
                ;;
            3)
                update_locale "zh_TW.UTF-8" "zh_TW.UTF-8"
                ;;
            0)
                break
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
        end_of
    done
}

shell_colorchange() {
    shell_colorchange_profile() {

    if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        sed -i '/^PS1=/d' ~/.bashrc
        echo "${colorchange}" >> ~/.bashrc
        # source ~/.bashrc
    else
        sed -i '/^PS1=/d' ~/.profile
        echo "${colorchange}" >> ~/.profile
        # source ~/.profile
    fi

    _green "变更完成！重新连接SSH后可查看变化！"
    hash -r
    end_of
    }

    need_root
    while true; do
        clear_screen
        echo "命令行美化工具"
        short_line
        echo -e "1. \033[1;32mroot \033[1;34mlocalhost \033[1;31m~ \033[0m${white}#"
        echo -e "2. \033[1;35mroot \033[1;36mlocalhost \033[1;33m~ \033[0m${white}#"
        echo -e "3. \033[1;31mroot \033[1;32mlocalhost \033[1;34m~ \033[0m${white}#"
        echo -e "4. \033[1;36mroot \033[1;33mlocalhost \033[1;37m~ \033[0m${white}#"
        echo -e "5. \033[1;37mroot \033[1;31mlocalhost \033[1;32m~ \033[0m${white}#"
        echo -e "6. \033[1;33mroot \033[1;34mlocalhost \033[1;35m~ \033[0m${white}#"
        echo -e "7. root localhost ~ #"
        short_line
        echo "0. 返回上一级"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1)
                colorchange="PS1='\[\033[1;32m\]\u\[\033[0m\]@\[\033[1;34m\]\h\[\033[0m\] \[\033[1;31m\]\w\[\033[0m\] # '"
                shell_colorchange_profile
                ;;
            2)
                colorchange="PS1='\[\033[1;35m\]\u\[\033[0m\]@\[\033[1;36m\]\h\[\033[0m\] \[\033[1;33m\]\w\[\033[0m\] # '"
                shell_colorchange_profile
                ;;
            3)
                colorchange="PS1='\[\033[1;31m\]\u\[\033[0m\]@\[\033[1;32m\]\h\[\033[0m\] \[\033[1;34m\]\w\[\033[0m\] # '"
                shell_colorchange_profile
                ;;
            4)
                colorchange="PS1='\[\033[1;36m\]\u\[\033[0m\]@\[\033[1;33m\]\h\[\033[0m\] \[\033[1;37m\]\w\[\033[0m\] # '"
                shell_colorchange_profile
                ;;
            5)
                colorchange="PS1='\[\033[1;37m\]\u\[\033[0m\]@\[\033[1;31m\]\h\[\033[0m\] \[\033[1;32m\]\w\[\033[0m\] # '"
                shell_colorchange_profile
                ;;
            6)
                colorchange="PS1='\[\033[1;33m\]\u\[\033[0m\]@\[\033[1;34m\]\h\[\033[0m\] \[\033[1;35m\]\w\[\033[0m\] # '"
                shell_colorchange_profile
                ;;
            7)
                colorchange=""
                shell_colorchange_profile
                ;;
            0)
                break
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
        end_of
    done
}

linux_trash() {
    need_root

    local trash_dir="$HOME/.local/share/Trash/files"

    while true; do
        local trash_status
        if ! grep -q "trash-put" "$HOME/.bashrc"; then
            trash_status="${yellow}未启用${white}"
        else
            trash_status="${green}已启用${white}"
        fi

        clear_screen
        echo -e "当前回收站 ${trash_status}"
        echo "启用后rm删除的文件先进入回收站，防止误删重要文件！"
        long_line
        ls -l --color=auto "$trash_dir" 2>/dev/null || echo "回收站为空"
        short_line
        echo "1. 启用回收站          2. 关闭回收站"
        echo "3. 还原内容            4. 清空回收站"
        short_line
        echo "0. 返回上一级"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1)
                install trash-cli
                sed -i '/alias rm/d' "$HOME/.bashrc"
                echo "alias rm='trash-put'" >> "$HOME/.bashrc"
                source "$HOME/.bashrc"
                _green "回收站已启用，删除的文件将移至回收站"
                sleep 2
                ;;
            2)
                remove trash-cli
                sed -i '/alias rm/d' "$HOME/.bashrc"
                echo "alias rm='rm -i'" >> "$HOME/.bashrc"
                source "$HOME/.bashrc"
                _yellow "回收站已关闭，文件将直接删除"
                sleep 2
                ;;
            3)
                echo -n "输入要还原的文件名: "
                read -r recover
                if [ -e "$trash_dir/$recover" ]; then
                    mv "$trash_dir/$recover" "$HOME/"
                    echo -n -e "$recover ${green}已还原到主目录${white}"
                else
                    _red "文件不存在"
                fi
                ;;
            4)
                echo -n "确认清空回收站? (y/n): "
                read -r confirm
                if [[ "$confirm" == "y" ]]; then
                    trash-empty
                    _green "回收站已清空"
                fi
                ;;
            0)
                break
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
        end_of
    done
}

cloudflare_ddns() {
    need_root
    set_script_dir
    ip_address
    local choice CFKEY CFUSER CFZONE_NAME CFRECORD_NAME CFRECORD_TYPE CFTTL

    while true; do
        clear_screen
        echo "Cloudflare ddns解析"
        short_line
        if [ -f /usr/local/bin/cf-ddns.sh ] || [ -f ${global_script_dir}/cf-v4-ddns.sh ]; then
            echo -e "${white}Cloudflare ddns: ${green}已安装${white}"
            crontab -l | grep "/usr/local/bin/cf-ddns.sh"
        else
            echo -e "${white}Cloudflare ddns: ${yellow}未安装${white}"
            echo "使用动态解析之前请解析一个域名，如ddns.cloudflare.com到你的当前公网IP"
        fi
        [ -n "${ipv4_address}" ] && echo "公网IPv4地址: ${ipv4_address}"
        [ -n "${ipv6_address}" ] && echo "公网IPv6地址: ${ipv6_address}"
        short_line
        echo "1. 设置DDNS动态域名解析     2. 删除DDNS动态域名解析"
        short_line
        echo "0. 返回上一级"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1)
                # 获取CFKEY
                while true; do
                    echo "cloudflare后台右上角我的个人资料，选择左侧API令牌，获取Global API Key"
                    echo "https://dash.cloudflare.com/profile/api-tokens"
                    echo -n "请输入你的Global API Key:"
                    read -r CFKEY
                    if [[ -n "$CFKEY" ]]; then
                        break
                    else
                        _red "CFKEY不能为空，请重新输入"
                    fi
                done

                # 获取CFUSER
                while true; do
                    echo -n "请输入你的Cloudflare管理员邮箱:"
                    read -r CFUSER
                    if [[ "$CFUSER" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                        break
                    else
                        _red "无效的邮箱格式，请重新输入"
                    fi
                done
                
                # 获取CFZONE_NAME
                while true; do
                    echo -n "请输入你的顶级域名 (如cloudflare.com): "
                    read -r CFZONE_NAME
                    if [[ "$CFZONE_NAME" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                        break
                    else
                        _red "无效的域名格式，请重新输入"
                    fi
                done

                # 获取CFRECORD_NAME
                while true; do
                    echo -n "请输入你的主域名 (如ddns.cloudflare.com): "
                    read -r CFRECORD_NAME
                    if [[ -n "$CFRECORD_NAME" ]]; then
                        break
                    else
                        _red "主机名不能为空请重新输入"
                    fi
                done

                # 获取CFRECORD_TYPE
                echo -n "请输入记录类型(A记录或AAAA记录，默认IPV4 A记录，回车使用默认值): "
                read -r CFRECORD_TYPE
                CFRECORD_TYPE=${CFRECORD_TYPE:-A}

                # 获取CFTTL
                echo -n "请输入TTL时间(120~86400秒，默认60秒,回车使用默认值): "
                read -r CFTTL
                CFTTL=${CFTTL:-60}

                curl -fsL -o ${global_script_dir}/cf-v4-ddns.sh "${github_Proxy}https://raw.githubusercontent.com/honeok/Tools/master/cf-v4-ddns.sh"

                sed -i "/^CFKEY=$/s/CFKEY=$/CFKEY=$CFKEY/" ${global_script_dir}/cf-v4-ddns.sh
                sed -i "/^CFUSER=$/s/CFUSER=$/CFUSER=$CFUSER/" ${global_script_dir}/cf-v4-ddns.sh
                sed -i "/^CFZONE_NAME=$/s/CFZONE_NAME=$/CFZONE_NAME=$CFZONE_NAME/" ${global_script_dir}/cf-v4-ddns.sh
                sed -i "/^CFRECORD_NAME=$/s/CFRECORD_NAME=$/CFRECORD_NAME=$CFRECORD_NAME/" ${global_script_dir}/cf-v4-ddns.sh
                sed -i "/^CFRECORD_TYPE=A$/s/CFRECORD_TYPE=A/CFRECORD_TYPE=$CFRECORD_TYPE/" ${global_script_dir}/cf-v4-ddns.sh
                sed -i "/^CFTTL=120$/s/CFTTL=120/CFTTL=$CFTTL/" ${global_script_dir}/cf-v4-ddns.sh

                # 复制脚本并设置权限
                cp ${global_script_dir}/cf-v4-ddns.sh /usr/local/bin/cf-ddns.sh && chmod +x /usr/local/bin/cf-ddns.sh

                check_crontab_installed

                if ! (crontab -l 2>/dev/null; echo "*/1 * * * * /usr/local/bin/cf-ddns.sh >/dev/null 2>&1") | crontab -; then
                    _red "无法自动添加Cron任务，请手动添加以下行到Crontab"
                    _yellow "*/1 * * * * /usr/local/bin/cf-ddns.sh >/dev/null 2>&1"
                    _yellow "按任意键继续"
                    read -n 1 -s -r -p ""
                fi

                _green "Cloudflare ddns安装完成"
                ;;
            2)
                if [ -f /usr/local/bin/cf-ddns.sh ]; then
                    rm -f /usr/local/bin/cf-ddns.sh
                else
                    _red "/usr/local/bin/cf-ddns.sh文件不存在"
                fi

                if crontab -l 2>/dev/null | grep -q '/usr/local/bin/cf-ddns.sh'; then
                    if (crontab -l 2>/dev/null | grep -v '/usr/local/bin/cf-ddns.sh') | crontab -; then
                        _green "定时任务已成功移除"
                    else
                        _red "无法移除定时任务，请手动移除"
                        _yellow "您可以手动删除定时任务中包含 '/usr/local/bin/cf-ddns.sh' 的那一行"
                        _yellow "按任意键继续"
                        read -n 1 -s -r -p ""
                    fi
                else
                    _red "定时任务中未找到与'/usr/local/bin/cf-ddns.sh'相关的任务"
                fi

                if [ -f ${global_script_dir}/cf-v4-ddns.sh ]; then
                    rm -f ${global_script_dir}/cf-v4-ddns.sh
                fi

                _green "Cloudflare ddns卸载完成"
                ;;
            0)
                break
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
        end_of
    done
}

server_reboot() {
    local choice
    echo -n -e "${yellow}现在重启服务器吗? (y/n): ${white}"
    read -r choice

    case $choice in
        [Yy])
            _green "已执行"
            reboot
            ;;
        *)
            _yellow "已取消"
            ;;
    esac
}

# 系统工具主菜单
linux_system_tools() {
    local choice
    while true; do
        clear_screen
        echo "▶ 系统工具"
        short_line
        echo "2. 修改登录密码"
        echo "3. root密码登录模式                    4. 安装Python指定版本"
        echo "5. 开放所有端口                        6. 修改SSH连接端口"
        echo "7. 优化DNS地址                         8. 一键重装系统"
        echo "9. 禁用root账户创建新账户              10. 切换IPV4/IPV6优先"
        short_line
        echo "11. 查看端口占用状态                   12. 修改虚拟内存大小"
        echo "13. 用户管理                           14. 用户/密码随机生成器"
        echo "15. 系统时区调整                       16. 设置XanMod BBR3"
        echo "17. 防火墙高级管理器                   18. 修改主机名"
        echo "19. 切换系统更新源                     20. 定时任务管理"
        short_line
        echo "21. 本机host解析                       22. Fail2banSSH防御程序"
        echo "23. 限流自动关机                       24. root私钥登录模式"
        echo "25. TG-bot系统监控预警                 26. 修复OpenSSH高危漏洞 (岫源)"
        echo "27. 红帽系Linux内核升级                28. Linux系统内核参数优化"
        echo "29. 病毒扫描工具                       30. 文件管理器"
        short_line
        echo "31. 切换系统语言                       32. 命令行美化工具"
        echo "33. 设置系统回收站"
        short_line
        echo "50. Cloudflare ddns解析                51. 一条龙系统调优"
        short_line
        echo "99. 重启服务器"
        short_line
        echo "0. 返回主菜单"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            2)
                _yellow "设置你的登录密码"
                passwd
                ;;
            3)
                need_root
                add_sshpasswd
                ;;
            4)
                need_root
                echo "Python版本管理"
                short_line
                echo "该功能可无缝安装Python官方支持的任何版本！"
                VERSION=$(python3 -V 2>&1 | awk '{print $2}')
                echo -e "当前python版本号: ${yellow}$VERSION${white}"
                short_line
                echo "推荐版本:  3.12    3.11    3.10    3.9    3.8    2.7"
                echo "查询更多版本: https://www.python.org/downloads/"
                short_line

                reading '请输入选项并按回车键确认: ' py_new_v

                if [[ "$py_new_v" == "0" ]]; then
                    end_of
                    linux_system_tools
                fi

                if ! grep -q "export PYENV_ROOT=\"$HOME/.pyenv\"" "$HOME/.bashrc"; then
                    if command -v yum >/dev/null 2>&1; then
                        install git
                        yum groupinstall "Development Tools" -y
                        install openssl-devel bzip2-devel libffi-devel ncurses-devel zlib-devel readline-devel sqlite-devel xz-devel findutils

                        curl -O https://www.openssl.org/source/openssl-1.1.1u.tar.gz
                        tar -xzf openssl-1.1.1u.tar.gz
                        cd openssl-1.1.1u || { _err_msg "$(_red '切换目录失败！')"; return 1; }
                        ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl shared zlib
                        make
                        make install
                        echo "/usr/local/openssl/lib" > /etc/ld.so.conf.d/openssl-1.1.1u.conf
                        ldconfig -v
                        cd .. || return 1

                        export LDFLAGS="-L/usr/local/openssl/lib"
                        export CPPFLAGS="-I/usr/local/openssl/include"
                        export PKG_CONFIG_PATH="/usr/local/openssl/lib/pkgconfig"
                    elif command -v apt >/dev/null 2>&1; then
                        install git
                        install build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev libgdbm-dev libnss3-dev libedit-dev
                    elif command -v apk >/dev/null 2>&1; then
                        install git
                        apk add --no-cache bash gcc musl-dev libffi-dev openssl-dev bzip2-dev zlib-dev readline-dev sqlite-dev libc6-compat linux-headers make xz-dev build-base ncurses-dev
                    else
                        _red "未知的包管理器！"
                        return 1
                    fi

                    curl https://pyenv.run | bash
                    cat << EOF >> ~/.bashrc

export PYENV_ROOT="\$HOME/.pyenv"
if [[ -d "\$PYENV_ROOT/bin" ]]; then
  export PATH="\$PYENV_ROOT/bin:\$PATH"
fi
eval "\$(pyenv init --path)"
eval "\$(pyenv init -)"
eval "\$(pyenv virtualenv-init -)"

EOF
                fi

                sleep 1
                source "$HOME/.bashrc"
                sleep 1
                pyenv install "$py_new_v"
                pyenv global "$py_new_v"

                rm -rf /tmp/python-build.*
                rm -rf "$(pyenv root)/cache/"*

                VERSION=$(python -V 2>&1 | awk '{print $2}')
                echo -e "当前Python版本号: ${yellow}$VERSION${white}"
                ;;
            5)
                need_root
                iptables_open >/dev/null 2>&1
                remove iptables-persistent ufw firewalld iptables-services >/dev/null 2>&1
                _green "端口已全部开放"
                ;;
            6)
                need_root

                while true; do
                    clear_screen

                    sed -i 's/#Port/Port/' /etc/ssh/sshd_config

                    # 读取当前的SSH端口号
                    current_port=$(grep -E '^[^#]*Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')

                    # 打印当前的SSH端口号
                    echo -e "当前的SSH端口号是: ${yellow}$current_port${white}"
                    short_line
                    echo "端口号范围10000到65535之间的数字 (按0退出)"

                    # 提示用户输入新的SSH端口号
                    echo -n "请输入新的SSH端口号:"
                    read -r new_port

                    # 判断端口号是否在有效范围内
                    if [[ $new_port =~ ^[0-9]+$ ]]; then  # 检查输入是否为数字
                        if [[ $new_port -ge 10000 && $new_port -le 65535 ]]; then
                            new_ssh_port
                        elif [[ $new_port -eq 0 ]]; then
                            break
                        else
                            _red "端口号无效，请输入10000到65535之间的数字"
                            end_of
                        fi
                    else
                        _red "输入无效，请输入数字"
                        end_of
                    fi
                done
                ;;
            7)
                need_root
                while true; do
                    clear_screen
                    echo "优化DNS地址"
                    short_line
                    echo "当前DNS地址"
                    cat /etc/resolv.conf
                    short_line
                    echo "国外DNS优化: "
                    echo "v4: 1.1.1.1 8.8.8.8"
                    echo "v6: 2606:4700:4700::1111 2001:4860:4860::8888"
                    echo "国内DNS优化: "
                    echo "v4: 223.5.5.5 183.60.83.19"
                    echo "v6: 2400:3200::1 2400:da00::6666"
                    short_line
                    echo "1. 设置DNS优化"
                    echo "2. 恢复DNS原有配置"
                    echo "3. 手动编辑DNS配置"
                    echo "4. 锁定/解锁DNS文件"
                    short_line
                    echo "0. 返回上一级"
                    short_line

                    reading '请输入选项并按回车键确认: ' choice

                    case $choice in
                        1)
                            bak_dns
                            set_dns
                            ;;
                        2)
                            rollbak_dns
                            ;;
                        3)
                            ( command -v vim >/dev/null 2>&1 && vim /etc/resolv.conf ) || vi /etc/resolv.conf
                            ;;
                        4)
                            dns_lock
                            ;;
                        0)
                            break
                            ;;
                        *)
                            _red "无效选项，请重新输入"
                            ;;
                    esac
                done
                ;;
            8)
                reinstall_system
                ;;
            9)
                need_root
                echo -n "请输入新用户名 (0退出):"
                read -r new_username

                if [ "$new_username" == "0" ]; then
                    end_of
                    linux_system_tools
                fi

                if id "$new_username" >/dev/null 2>&1; then
                    _red "用户$new_username已存在"
                    end_of
                    linux_system_tools
                fi
                # 创建用户
                useradd -m -s /bin/bash "$new_username" || {
                    _red "创建用户失败"
                    end_of
                    linux_system_tools
                }
                # 设置用户密码
                passwd "$new_username" || {
                    _red "设置用户密码失败"
                    end_of
                    linux_system_tools
                }
                # 更新sudoers文件
                echo "$new_username ALL=(ALL:ALL) ALL" | tee -a /etc/sudoers || {
                    _red "更新sudoers文件失败"
                    end_of
                    linux_system_tools
                }
                # 锁定root用户
                passwd -l root || {
                    _red "锁定root用户失败"
                    end_of
                    linux_system_tools
                }

                _green "操作完成"
                ;;
            10)
                while true; do
                    clear_screen
                    echo "设置v4/v6优先级"
                    short_line
                    ipv6_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6)

                    if [ "$ipv6_disabled" -eq 1 ]; then
                        echo -e "当前网络优先级设置:${yellow}IPv4${white}优先"
                    else
                        echo -e "当前网络优先级设置:${yellow}IPv6${white}优先"
                    fi
                    echo ""
                    short_line
                    echo "1. IPv4 优先          2. IPv6 优先          3. IPv6 修复工具          0. 退出"
                    short_line
                    echo -n "选择优先的网络:"
                    read -r choice

                    case $choice in
                        1)
                            sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
                            _green "已切换为IPv4优先"
                            ;;
                        2)
                            sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1
                            _green "已切换为IPv6优先"
                            ;;
                        3)
                            echo "该功能由jhb提供，感谢！"
                            bash <(curl -L -s jhb.ovh/jb/v6.sh)
                            ;;
                        0)
                            break
                            ;;
                        *)
                            _red "无效选项，请重新输入"
                            ;;
                    esac
                done
                ;;
            11)
                clear_screen
                ss -tulnape
                ;;
            12)
                need_root
                while true; do
                    clear_screen
                    echo "设置虚拟内存"
                    # 获取当前虚拟内存使用情况
                    # swap_used=$(free -m | awk 'NR==3{print $3}')
                    swap_total=$(free -m | awk 'NR==3{print $2}')
                    swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dMB/%dMB (%d%%)", used, total, percentage}')
                    _yellow "当前虚拟内存 ${swap_info}"
                    short_line
                    echo "1. 分配1024MB         2. 分配2048MB         3. 自定义大小         0. 退出"
                    short_line
                    
                    reading '请输入选项并按回车键确认: ' choice

                    case $choice in
                        1)
                            add_swap 1024
                            _green "已设置虚拟内存为1024MB"
                            ;;
                        2)
                            add_swap 2048
                            _green "已设置虚拟内存为2048MB"
                            ;;
                        3)
                            echo -n "请输入虚拟内存大小MB: "
                            read -r new_swap
                            if [[ "$new_swap" =~ ^[0-9]+$ ]] && [[ "$new_swap" -gt 0 ]]; then
                                add_swap "$new_swap"
                                _green "已设置自定义虚拟内存为 ${new_swap}MB"
                            else
                                _red "无效输入，请输入正整数"
                            fi
                            ;;
                        0)
                            break
                            ;;
                        *)
                            _red "无效选项，请重新输入"
                            ;;
                    esac
                done
                ;;
            13)
                while true; do
                    need_root
                    echo "用户列表"
                    long_line
                    printf "%-24s %-34s %-20s %-10s\n" "用户名" "用户权限" "用户组" "sudo权限"
                    while IFS=: read -r username _ _ _ _ homedir _; do
                        groups=$(groups "$username" | cut -d : -f 2)
                        sudo_status=$(sudo -n -lU "$username" 2>/dev/null | grep -q '(ALL : ALL)' && echo "Yes" || echo "No")
                        printf "%-20s %-30s %-20s %-10s\n" "$username" "$homedir" "$groups" "$sudo_status"
                    done < /etc/passwd
                    echo ""
                    echo "账户操作"
                    short_line
                    echo "1. 创建普通账户             2. 创建高级账户"
                    short_line
                    echo "3. 赋予最高权限             4. 取消最高权限"
                    short_line
                    echo "5. 删除账号"
                    short_line
                    echo "0. 返回上一级选单"
                    short_line

                    reading '请输入选项并按回车键确认: ' choice

                    case $choice in
                        1)
                            echo -n "请输入新用户名:"
                            read -r new_username

                            useradd -m -s /bin/bash "$new_username" && \
                            passwd "$new_username" && \
                            _green "普通账户创建完成"
                            ;;
                        2)
                            echo -n "请输入新用户名:"
                            read -r new_username

                            useradd -m -s /bin/bash "$new_username" && \
                            passwd "$new_username" && \
                            echo "$new_username ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers && \
                            _green "高级账户创建完成"
                            ;;
                        3)
                            echo -n "请输入新用户名:"
                            read -r username

                            echo "$username ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers && \
                            _green "已赋予$username Sudo权限"
                            ;;
                        4)
                            echo -n "请输入新用户名:"
                            read -r username
                            # 从sudoers文件中移除用户的sudo权限
                            if sudo sed -i "/^$username\sALL=(ALL:ALL)\sALL/d" /etc/sudoers; then
                                _green "已取消 $username的Sudo权限"
                            else
                                _red "取消Sudo权限失败"
                            fi
                            ;;
                        5)
                            echo -n "请输入要删除的用户名:"
                            read -r username

                            # 删除用户及其主目录
                            userdel -r "$username" && \
                            _green "$username账号已删除"
                            ;;
                        0)
                            break
                            ;;
                        *)
                            _red "无效选项，请重新输入"
                            ;;
                    esac
                done
                ;;
            14)
                clear_screen
                echo "随机用户名"
                short_line
                for i in {1..5}; do
                    username="user$(< /dev/urandom tr -dc _a-z0-9 | head -c6)"
                    echo "随机用户名 $i: $username"
                done

                echo ""
                echo "随机姓名"
                short_line
                first_names=("John" "Jane" "Michael" "Emily" "David" "Sophia" "William" "Olivia" "James" "Emma" "Ava" "Liam" "Mia" "Noah" "Isabella")
                last_names=("Smith" "Johnson" "Brown" "Davis" "Wilson" "Miller" "Jones" "Garcia" "Martinez" "Williams" "Lee" "Gonzalez" "Rodriguez" "Hernandez")

                # 生成5个随机用户姓名
                for i in {1..5}; do
                    first_name_index=$((RANDOM % ${#first_names[@]}))
                    last_name_index=$((RANDOM % ${#last_names[@]}))
                    user_name="${first_names[$first_name_index]} ${last_names[$last_name_index]}"
                    echo "随机用户姓名 $i: $user_name"
                done

                echo ""
                echo "随机UUID"
                short_line
                for i in {1..5}; do
                    uuid=$(cat /proc/sys/kernel/random/uuid)
                    echo "随机UUID $i: $uuid"
                done

                echo ""
                echo "16位随机密码"
                short_line
                for i in {1..5}; do
                    password=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c16)
                    echo "随机密码 $i: $password"
                done

                echo ""
                echo "32位随机密码"
                short_line
                for i in {1..5}; do
                    password=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)
                    echo "随机密码 $i: $password"
                done
                echo ""
                ;;
            15)
                need_root
                while true; do
                    clear_screen
                    # 获取当前系统时区
                    local timezone
                    timezone=$(current_timezone)

                    # 获取当前系统时间
                    local current_time
                    current_time=$(date +"%Y-%m-%d %H:%M:%S")

                    # 显示时区和时间
                    _yellow "当前系统时区:$timezone"
                    _yellow "当前系统时间:$current_time"

                    echo ""
                    echo "时区切换"
                    echo "------------亚洲------------"
                    echo "1. 中国上海时间              2. 中国香港时间"
                    echo "3. 日本东京时间              4. 韩国首尔时间"
                    echo "5. 新加坡时间                6. 印度加尔各答时间"
                    echo "7. 阿联酋迪拜时间            8. 澳大利亚悉尼时间"
                    echo "9. 以色列特拉维夫时间        10. 马尔代夫时间"
                    echo "------------欧洲------------"
                    echo "11. 英国伦敦时间             12. 法国巴黎时间"
                    echo "13. 德国柏林时间             14. 俄罗斯莫斯科时间"
                    echo "15. 荷兰尤特赖赫特时间       16. 西班牙马德里时间"
                    echo "17. 瑞士苏黎世时间           18. 意大利罗马时间"
                    echo "------------美洲------------"
                    echo "21. 美国西部时间             22. 美国东部时间"
                    echo "23. 加拿大时间               24. 墨西哥时间"
                    echo "25. 巴西时间                 26. 阿根廷时间"
                    echo "27. 智利时间                 28. 哥伦比亚时间"
                    echo "------------非洲------------"
                    echo "31. 南非约翰内斯堡时间       32. 埃及开罗时间"
                    echo "33. 摩洛哥拉巴特时间         34. 尼日利亚拉各斯时间"
                    short_line
                    echo "0. 返回上一级选单"
                    short_line

                    reading '请输入选项并按回车键确认: ' choice

                    case $choice in
                        1) set_timedate Asia/Shanghai ;;
                        2) set_timedate Asia/Hong_Kong ;;
                        3) set_timedate Asia/Tokyo ;;
                        4) set_timedate Asia/Seoul ;;
                        5) set_timedate Asia/Singapore ;;
                        6) set_timedate Asia/Kolkata ;;
                        7) set_timedate Asia/Dubai ;;
                        8) set_timedate Australia/Sydney ;;
                        9) set_timedate Asia/Tel_Aviv ;;
                        10) set_timedate Indian/Maldives ;;
                        11) set_timedate Europe/London ;;
                        12) set_timedate Europe/Paris ;;
                        13) set_timedate Europe/Berlin ;;
                        14) set_timedate Europe/Moscow ;;
                        15) set_timedate Europe/Amsterdam ;;
                        16) set_timedate Europe/Madrid ;;
                        17) set_timedate Europe/Zurich ;;
                        18) set_timedate Europe/Rome ;;
                        21) set_timedate America/Los_Angeles ;;
                        22) set_timedate America/New_York ;;
                        23) set_timedate America/Vancouver ;;
                        24) set_timedate America/Mexico_City ;;
                        25) set_timedate America/Sao_Paulo ;;
                        26) set_timedate America/Argentina/Buenos_Aires ;;
                        27) set_timedate America/Santiago ;;
                        28) set_timedate America/Bogota ;;
                        31) set_timedate Africa/Johannesburg ;;
                        32) set_timedate Africa/Cairo ;;
                        33) set_timedate Africa/Casablanca ;;
                        34) set_timedate Africa/Lagos ;;
                        0) break ;;  # 退出循环
                        *) _red "无效选项，请重新输入" ;;
                    esac
                    end_of
                done
                ;;
            16)
                xanmod_bbr3
                ;;
            17)
                need_root
                while true; do
                    if dpkg -l | grep -q iptables-persistent; then
                        clear_screen
                        echo "高级防火墙管理"
                        short_line
                        iptables -L INPUT
                        echo ""
                        echo "防火墙管理"
                        short_line
                        echo "1. 开放指定端口                 2.  关闭指定端口"
                        echo "3. 开放所有端口                 4.  关闭所有端口"
                        short_line
                        echo "5. IP白名单                    6.  IP黑名单"
                        echo "7. 清除指定IP"
                        short_line
                        echo "11. 允许PING                  12. 禁止PING"
                        short_line
                        echo "99. 卸载防火墙"
                        short_line
                        echo "0. 返回上一级选单"
                        short_line
                        reading '请输入选项并按回车键确认: ' choice

                        case $choice in
                            1)
                                echo -n -e "${yellow}请输入开放的端口号: ${white}"
                                read -r o_port
                                sed -i "/COMMIT/i -A INPUT -p tcp --dport $o_port -j ACCEPT" /etc/iptables/rules.v4
                                sed -i "/COMMIT/i -A INPUT -p udp --dport $o_port -j ACCEPT" /etc/iptables/rules.v4
                                iptables-restore < /etc/iptables/rules.v4
                                ;;
                            2)
                                echo -n -e "${yellow}请输入关闭的端口号: ${white}"
                                read -r c_port
                                sed -i "/--dport $c_port/d" /etc/iptables/rules.v4
                                iptables-restore < /etc/iptables/rules.v4
                                ;;
                            3)
                                current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')
                                cat > /etc/iptables/rules.v4 << EOF
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A FORWARD -i lo -j ACCEPT
-A INPUT -p tcp --dport $current_port -j ACCEPT
COMMIT
EOF
                                iptables-restore < /etc/iptables/rules.v4
                                ;;
                            4)
                                current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')
                                cat > /etc/iptables/rules.v4 << EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A FORWARD -i lo -j ACCEPT
-A INPUT -p tcp --dport $current_port -j ACCEPT
COMMIT
EOF
                                iptables-restore < /etc/iptables/rules.v4
                                ;;
                            5)
                                echo -n -e "${yellow}请输入放行的IP:${white}"
                                read -r o_ip
                                sed -i "/COMMIT/i -A INPUT -s $o_ip -j ACCEPT" /etc/iptables/rules.v4
                                iptables-restore < /etc/iptables/rules.v4
                                ;;
                            6)
                                echo -n -e "${yellow}请输入封锁的IP: ${white}"
                                read -r c_ip
                                sed -i "/COMMIT/i -A INPUT -s $c_ip -j DROP" /etc/iptables/rules.v4
                                iptables-restore < /etc/iptables/rules.v4
                                ;;
                            7)
                                echo -n -e "${yellow}请输入清除的IP: ${white}"
                                read -r d_ip
                                sed -i "/-A INPUT -s $d_ip/d" /etc/iptables/rules.v4
                                iptables-restore < /etc/iptables/rules.v4
                                ;;
                            11)
                                sed -i '$i -A INPUT -p icmp --icmp-type echo-request -j ACCEPT' /etc/iptables/rules.v4
                                sed -i '$i -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT' /etc/iptables/rules.v4
                                iptables-restore < /etc/iptables/rules.v4
                                ;;
                            12)
                                sed -i "/icmp/d" /etc/iptables/rules.v4
                                iptables-restore < /etc/iptables/rules.v4
                                ;;
                            99)
                                remove iptables-persistent
                                rm -f /etc/iptables/rules.v4
                                break
                                ;;
                            0)
                                break # 跳出循环，退出菜单
                                ;;
                            *)
                                _red "无效选项，请重新输入"
                                ;;
                        esac
                    else
                        clear_screen
                        echo "将为你安装防火墙，该防火墙仅支持Debian/Ubuntu"
                        short_line
                        echo -n -e "${yellow}确定继续吗? (y/n): ${white}"
                        read -r choice

                        case $choice in
                            [Yy])
                                if [ -r /etc/os-release ]; then
                                    # shellcheck source=/dev/null
                                    . /etc/os-release
                                    if [ "$ID" != "debian" ] && [ "$ID" != "ubuntu" ]; then
                                        echo "当前环境不支持，仅支持Debian和Ubuntu系统"
                                        end_of
                                        linux_system_tools
                                    fi
                                else
                                    echo "无法确定操作系统类型"
                                    break
                                fi

                                clear_screen
                                iptables_open
                                remove iptables-persistent ufw
                                rm -f /etc/iptables/rules.v4

                                apt update -y && apt install -y iptables-persistent

                                current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')
                                cat > /etc/iptables/rules.v4 << EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A FORWARD -i lo -j ACCEPT
-A INPUT -p tcp --dport $current_port -j ACCEPT
COMMIT
EOF
                                iptables-restore < /etc/iptables/rules.v4
                                systemctl enable netfilter-persistent
                                _green "防火墙安装完成"
                                end_of
                                ;;
                            *)
                                _yellow "已取消"
                                break
                                ;;
                        esac
                    fi
                done
                ;;
            18)
                need_root
                while true; do
                    clear_screen
                    current_hostname=$(hostname)
                    echo -e "当前主机名: $current_hostname"
                    short_line
                    echo -n "请输入新的主机名(输入0退出): "
                    read -r new_hostname

                    if [ -n "$new_hostname" ] && [ "$new_hostname" != "0" ]; then
                        if [ -f /etc/alpine-release ]; then
                            # Alpine
                            echo "$new_hostname" > /etc/hostname
                            hostname "$new_hostname"
                        else
                            # 其他系统，如 Debian, Ubuntu, CentOS 等
                            hostnamectl set-hostname "$new_hostname"
                            sed -i "s/$current_hostname/$new_hostname/g" /etc/hostname
                            systemctl restart systemd-hostnamed
                        fi

                        if grep -q "127.0.0.1" /etc/hosts; then
                            sed -i "s/127.0.0.1 .*/127.0.0.1       $new_hostname localhost localhost.localdomain/g" /etc/hosts
                        else
                            echo "127.0.0.1       $new_hostname localhost localhost.localdomain" >> /etc/hosts
                        fi

                        if grep -q "^::1" /etc/hosts; then
                            sed -i "s/^::1 .*/::1             $new_hostname localhost localhost.localdomain ipv6-localhost ipv6-loopback/g" /etc/hosts
                        else
                            echo "::1             $new_hostname localhost localhost.localdomain ipv6-localhost ipv6-loopback" >> /etc/hosts
                        fi

                        echo "主机名已更改为: $new_hostname"
                        sleep 1
                    else
                        _yellow "已退出，未更改主机名"
                        break
                    fi
                done
                ;;
            19)
                linux_mirror
                ;;
            20)
                cron_manager
                ;;
            21)
                need_root
                while true; do
                    clear_screen
                    echo "本机host解析列表"
                    echo "如果你在这里添加解析匹配，将不再使用动态解析了"
                    cat /etc/hosts
                    echo ""
                    echo "操作"
                    short_line
                    echo "1. 添加新的解析              2. 删除解析地址"
                    short_line
                    echo "0. 返回上一级选单"
                    short_line

                    reading '请输入选项并按回车键确认: ' host_dns

                    case $host_dns in
                        1)
                            echo -n "请输入新的解析记录，格式:110.25.5.33 honeok.com:"
                            read -r addhost

                            echo "$addhost" >> /etc/hosts
                            ;;
                        2)
                            echo -n "请输入需要删除的解析内容关键字:"
                            read -r delhost

                            sed -i "/$delhost/d" /etc/hosts
                            ;;
                        0)
                            break
                            ;;
                        *)
                            _red "无效选项，请重新输入"
                            ;;
                    esac
                done
                ;;
            22)
                need_root
                while true; do
                    if docker inspect fail2ban >/dev/null 2>&1 ; then
                    	clear_screen
                    	echo "SSH防御程序已启动"
                    	short_line
                    	echo "1. 查看SSH拦截记录"
                    	echo "2. 查看日志实时监控"
                    	short_line
                    	echo "9. 卸载防御程序"
                    	short_line
                    	echo "0. 退出"
                    	short_line

                        reading '请输入选项并按回车键确认: ' choice

                    	case $choice in
                    		1)
                                short_line
                                fail2ban_sshd
                                short_line
                                end_of
                                ;;
                    		2)
                                tail -f /data/docker_data/fail2ban/config/log/fail2ban/fail2ban.log
                                break
                                ;;
                    		9)
                                cd /data/docker_data/fail2ban || { _err_msg "$(_red '切换目录失败！')"; return 1; }
                                docker_compose down_all

                                [ -d /data/docker_data/fail2ban ] && rm -rf /data/docker_data/fail2ban
                                ;;
                    		0)
                                break
                                ;;
                    		*)
                                _red "无效选项，请重新输入"
                                ;;
                    	esac
                    elif [ -x "$(command -v fail2ban-client)" ] ; then
                    	clear_screen
                    	echo "卸载旧版fail2ban"
                    	echo -n -e "${yellow}确定继续吗? (y/n): ${white}"
                    	read -r choice

                    	case $choice in
                    		[Yy])
                                remove fail2ban
                                rm -rf /etc/fail2ban
                                _green "Fail2Ban防御程序已卸载"
                                end_of
                                ;;
                    		*)
                                _yellow "已取消"
                                break
                                ;;
                    	esac
                    else
                    	clear_screen
                    	echo "fail2ban是一个SSH防止暴力破解工具"
                    	echo "官网介绍: https://github.com/fail2ban/fail2ban"
                    	long_line
                    	echo "工作原理:研判非法IP恶意高频访问SSH端口，自动进行IP封锁"
                    	long_line
                    	echo -n -e "${yellow}确定继续吗? (y/n): ${white}"
                    	read -r choice

                    	case $choice in
                    		[Yy])
                                clear_screen
                                install_docker
                                fail2ban_install_sshd

                                fail2ban_status
                                _green "Fail2Ban防御程序已开启"
                                end_of
                                ;;
                    		*)
                                _yellow "已取消"
                                break
                                ;;
                    	esac
                    fi
                done
                ;;
            23)
                need_root
                set_script_dir
                while true; do
                    clear_screen
                    echo "限流关机功能"
                    long_line
                    echo "当前流量使用情况，重启服务器流量计算会清零！"
                    network_usage_status
                    echo "$network_usage_summary"

                    # 检查是否存在limitoff.sh文件
                    if [ -f ${global_script_dir}/limitoff.sh ]; then
                        # 获取threshold_gb的值
                        local rx_threshold_gb tx_threshold_gb
                        rx_threshold_gb=$(sed -n 's/.*rx_threshold_gb=\([0-9]\+\).*/\1/p' "${global_script_dir}/limitoff.sh")
                        tx_threshold_gb=$(sed -n 's/.*tx_threshold_gb=\([0-9]\+\).*/\1/p' "${global_script_dir}/limitoff.sh")
                        echo -e "${green}当前设置的进站限流阈值为: ${yellow}${rx_threshold_gb}${green}GB${white}"
                        echo -e "${green}当前设置的出站限流阈值为: ${yellow}${tx_threshold_gb}${green}GB${white}"
                    else
                        _red "当前未启用限流关机功能"
                    fi
                    echo ""
                    long_line
                    echo "系统每分钟会检测实际流量是否到达阈值，到达后会自动关闭服务器！"
                    echo "1. 开启限流关机功能    2. 停用限流关机功能    0. 退出"
                    long_line
                    reading '请输入选项并按回车键确认: ' choice

                    case $choice in
                        1)
                            echo "如果实际服务器就100G流量，可设置阈值为95G提前关机，以免出现流量误差或溢出"
                            echo -n "请输入进站流量阈值(单位为GB): "
                            read -r rx_threshold_gb
                            echo -n "请输入出站流量阈值(单位为GB): "
                            read -r tx_threshold_gb
                            echo -n "请输入流量重置日期(默认每月1日重置): "
                            read -r reset_day
                            reset_day=${reset_day:-1}

                            cd ${global_script_dir} || { _err_msg "$(_red '切换目录失败！')"; return 1; }
                            curl -fsL -O "${github_Proxy}https://raw.githubusercontent.com/honeok/Tools/master/limitoff.sh"
                            chmod +x ${global_script_dir}/limitoff.sh
                            sed -i "s/110/$rx_threshold_gb/g" ${global_script_dir}/limitoff.sh
                            sed -i "s/120/$tx_threshold_gb/g" ${global_script_dir}/limitoff.sh
                            check_crontab_installed
                            crontab -l | grep -v "${global_script_dir}/limitoff.sh" | crontab -
                            (crontab -l ; echo "* * * * * ${global_script_dir}/limitoff.sh") | crontab - >/dev/null 2>&1
                            crontab -l | grep -v 'reboot' | crontab -
                            (crontab -l ; echo "0 1 $reset_day * * reboot") | crontab - >/dev/null 2>&1
                            _green "限流关机已开启"
                            ;;
                        2)
                            check_crontab_installed
                            crontab -l | grep -v "${global_script_dir}/limitoff.sh" | crontab -
                            crontab -l | grep -v 'reboot' | crontab -
                            rm -f ${global_script_dir}/limitoff.sh
                            _green "限流关机已卸载"
                            ;;
                        *)
                            break
                            ;;
                    esac
                done
                ;;
            24)
                need_root
                echo "root私钥登录模式"
                long_line
                echo "将会生成密钥对，更安全的方式SSH登录"
                echo -n -e "${yellow}确定继续吗? (y/n): ${white}"
                read -r choice

                case $choice in
                    [Yy])
                        clear_screen
                        add_sshkey
                        ;;
                    [Nn])
                        _yellow "已取消"
                        ;;
                    *)
                        _red "无效选项，请重新输入"
                        ;;
                esac
                ;;
            25)
                telegram_bot
                ;;
            26)
                need_root
                curl -fsL -o "upgrade_openssh.sh" "${github_Proxy}https://raw.githubusercontent.com/honeok/Tools/master/upgrade_ssh.sh"
                chmod +x upgrade_openssh.sh
                ./upgrade_openssh.sh
                rm -f upgrade_openssh.sh
                ;;
            27)
                redhat_kernel_update
                ;;
            28)
                need_root
                while true; do
                    clear_screen
                    echo "Linux系统内核参数优化"
                    long_line
                    echo "提供多种系统参数调优模式,用户可以根据自身使用场景进行选择切换"
                    _yellow "生产环境请谨慎使用!"
                    short_line
                    echo "1. 高性能优化模式   :     最大化系统性能，优化文件描述符、虚拟内存、网络设置、缓存管理和CPU设置"
                    echo "2. 均衡优化模式     :     在性能与资源消耗之间取得平衡，适合日常使用"
                    echo "3. 网站优化模式     :     针对网站服务器进行优化，提高并发连接处理能力，响应速度和整体性能"
                    echo "4. 直播优化模式     :     针对直播推流的特殊需求进行优化，减少延迟，提高传输性能"
                    echo "5. 游戏服优化模式   :     针对游戏服务器进行优化，提高并发处理能力和响应速度"
                    echo "6. 还原默认设置     :     将系统设置还原为默认配置"
                    short_line
                    echo "0. 返回上一级"
                    short_line

                    reading '请输入选项并按回车键确认: ' choice

                    case $choice in
                        1)
                            clear_screen
                            optimization_mode="高性能优化模式"
                            optimize_high_performance
                            ;;
                        2)
                            clear_screen
                            optimize_balanced
                            ;;
                        3)
                            clear_screen
                            optimize_web_server
                            ;;
                        4)
                            clear_screen
                            optimization_mode="直播优化模式"
                            optimize_high_performance
                            ;;
                        5)
                            clear_screen
                            optimization_mode="游戏服优化模式"
                            optimize_high_performance
                            ;;
                        6)
                            clear_screen
                            restore_defaults
                            ;;
                        0)
                            break
                            ;;
                        *)
                            _red "无效选项，请重新输入"
                            ;;
                    esac
                    end_of
                done
                ;;
            29)
                clamav_antivirus
                ;;
            30)
                file_manage
                ;;
            31)
                linux_language
                ;;
            32)
                shell_colorchange
                ;;
            33)
                linux_trash
                ;;
            50)
                cloudflare_ddns
                ;;
            51)
                need_root
                echo "一条龙系统调优"
                long_line
                echo "将对以下内容进行操作与优化"
                echo "1. 更新系统到最新"
                echo "2. 清理系统垃圾文件"
                echo -e "3. 设置虚拟内存${yellow}1G${white}"
                echo -e "4. 设置SSH端口号为${yellow}22166${white}"
                echo -e "5. 开放所有端口"
                echo -e "6. 开启${yellow}BBR${white}加速"
                echo -e "7. 设置时区到${yellow}上海${white}"
                echo -e "8. 自动优化DNS地址${yellow}海外: 1.1.1.1 8.8.8.8  国内: 223.5.5.5 ${white}"
                echo -e "9. 安装常用工具${yellow}docker wget sudo tar unzip socat btop nano vim${white}"
                echo -e "10. Linux系统内核参数优化切换到${yellow}均衡优化模式${white}"
                long_line

                echo -n -e "${yellow}确定一键调优吗? (y/n): ${white}"
                read -r choice

                case $choice in
                    [Yy])
                        clear_screen
                        long_line
                        linux_update
                        echo -e "[${green}OK${white}] 1/10. 更新系统到最新"
                        long_line
                        linux_clean
                        echo -e "[${green}OK${white}] 2/10. 清理系统垃圾文件"
                        long_line
                        new_swap=1024
                        add_swap
                        echo -e "[${green}OK${white}] 3/10. 设置虚拟内存${yellow}1G${white}"
                        long_line
                        new_port=22166
                        new_ssh_port
                        echo -e "[${green}OK${white}] 4/10. 设置SSH端口号为${yellow}${new_port}${white}"
                        long_line
                        iptables_open
                        remove iptables-persistent ufw firewalld iptables-services >/dev/null 2>&1
                        echo -e "[${green}OK${white}] 5/10. 开放所有端口"
                        long_line
                        bbr_on
                        echo -e "[${green}OK${white}] 6/10. 开启${yellow}BBR${white}加速"
                        long_line
                        set_timedate Asia/Shanghai
                        echo -e "[${green}OK${white}] 7/10. 设置时区到${yellow}上海${white}"
                        long_line
                        bak_dns
                        set_dns
                        echo -e "[${green}OK${white}] 8/10. 自动优化DNS地址${yellow}${white}"
                        long_line
                        install_docker
                        install wget sudo tar unzip socat btop nano vim
                        echo -e "[${green}OK${white}] 9/10. 安装常用工具${yellow}docker wget sudo tar unzip socat btop${white}"
                        long_line
                        optimize_balanced
                        echo -e "[${green}OK${white}] 10/10. Linux系统内核参数优化"
                        echo -e "${green}一条龙系统调优已完成${white}"
                        ;;
                    [Nn])
                        echo "已取消"
                        ;;
                    *)
                        _red "无效选项，请重新输入"
                        ;;
                esac
                ;;
            99)
                clear_screen
                server_reboot
                ;;
            0)
                menu
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
        end_of
    done
}

## 工作区

tmux_run() {
    # 检查会话是否已经存在
    if ! tmux has-session -t "$session_name" 2>/dev/null; then
        # 会话不存在,创建一个新的会话
        tmux new -s "$session_name"
    else
        # 会话存在附加到这个会话
        tmux attach-session -t "$session_name"
    fi
}

tmux_run_d() {
    base_name="tmuxd"
    tmuxd_ID=1

    # 检查会话是否存在的函数
    session_exists() {
        tmux has-session -t "$1" 2>/dev/null
    }

    # 循环直到找到一个不存在的会话名称
    while session_exists "$base_name-$tmuxd_ID"; do
        tmuxd_ID=$((tmuxd_ID + 1))
    done

    # 创建新的tmux会话
    tmux new -d -s "$base_name-$tmuxd_ID" "$tmuxd"
}

linux_workspace() {
    while true; do
        clear_screen
        echo "▶ 我的工作区"
        echo "系统将为你提供可以后台常驻运行的工作区，你可以用来执行长时间的任务"
        echo "即使你断开SSH，工作区中的任务也不会中断，后台常驻任务"
        echo "提示: 进入工作区后使用Ctrl+b再单独按d，退出工作区！"
        short_line
        echo "1. 1号工作区"
        echo "2. 2号工作区"
        echo "3. 3号工作区"
        echo "4. 4号工作区"
        echo "5. 5号工作区"
        echo "6. 6号工作区"
        echo "7. 7号工作区"
        echo "8. 8号工作区"
        echo "9. 9号工作区"
        echo "10. 10号工作区"
        short_line
        echo "98. SSH常驻模式"
        echo "99. 工作区管理"
        short_line
        echo "0. 返回主菜单"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1)
                clear_screen
                install tmux
                session_name="work1"
                tmux_run
                ;;
            2)
                clear_screen
                install tmux
                session_name="work2"
                tmux_run
                ;;
            3)
                clear_screen
                install tmux
                session_name="work3"
                tmux_run
                ;;
            4)
                clear_screen
                install tmux
                session_name="work4"
                tmux_run
                ;;
            5)
                clear_screen
                install tmux
                session_name="work5"
                tmux_run
                ;;
            6)
                clear_screen
                install tmux
                session_name="work6"
                tmux_run
                ;;
            7)
                clear_screen
                install tmux
                session_name="work7"
                tmux_run
                ;;
            8)
                clear_screen
                install tmux
                session_name="work8"
                tmux_run
                ;;
            9)
                clear_screen
                install tmux
                session_name="work9"
                tmux_run
                ;;
            10)
                clear_screen
                install tmux
                session_name="work10"
                tmux_run
                ;;
            98)
                while true; do
                    clear_screen
                    if grep -q 'tmux attach-session -t sshd || tmux new-session -s sshd' ~/.bashrc; then
                        tmux_sshd_status="${green}开启${white}"
                    else
                        tmux_sshd_status="${gray}关闭${white}"
                    fi
                    echo -e "SSH常驻模式 ${tmux_sshd_status}"
                    echo "开启后SSH连接后会直接进入常驻模式，直接回到之前的工作状态"
                    short_line
                    echo "1. 开启            2. 关闭"
                    short_line
                    echo "0. 返回上一级"
                    short_line

                    reading '请输入选项并按回车键确认: ' gongzuoqu_del

                    case "$gongzuoqu_del" in
                        1)
                            install tmux
                            session_name="sshd"
                            grep -q "tmux attach-session -t sshd" "$HOME/.bashrc" || echo -e "\n# 自动进入 tmux 会话\nif [[ -z \"\$TMUX\" ]]; then\n    tmux attach-session -t sshd || tmux new-session -s sshd\nfi" >> "$HOME/.bashrc"
                            source "$HOME/.bashrc"
                            tmux_run
                            ;;
                        2)
                            sed -i '/# 自动进入 tmux 会话/,+4d' ~/.bashrc
                            tmux kill-window -t sshd
                            ;;
                        0)
                            break
                            ;;
                        *)
                            _red "无效选项，请重新输入"
                            ;;
                    esac
                done
                ;;
            99)
                while true; do
                    clear_screen
                    echo "当前已存在的工作区列表"
                    short_line
                    tmux list-sessions
                    short_line
                    echo "1. 创建/进入工作区"
                    echo "2. 注入命令到后台工作区"
                    echo "3. 删除指定工作区"
                    short_line
                    echo "0. 返回上一级"
                    short_line

                    reading '请输入选项并按回车键确认: ' gongzuoqu_del

                    case "$gongzuoqu_del" in
                        1)
                            echo -n "请输入你创建或进入的工作区名称，如1001 honeok work1:"
                            read -r session_name
                            tmux_run
                            ;;
                        2)
                            echo -n "请输入你要后台执行的命令，如: curl -fsL https://get.docker.com | sh:"
                            read -r tmuxd
                            tmux_run_d
                            ;;
                        3)
                            echo -n "请输入要删除的工作区名称:"
                            read -r workspace_name
                            tmux kill-window -t "$workspace_name"
                            ;;
                        0)
                            break
                            ;;
                        *)
                            _red "无效选项，请重新输入"
                            ;;
                    esac
                done
                ;;
            0)
                menu
                ;;
            *)
                _red "无效选项，请重新输入"
                ;;
        esac
        end_of
    done
}

## VPS测试脚本

servertest_script() {
    need_root
    local choice
    while true; do
        clear_screen
        echo "▶ 测试脚本合集"
        short_line
        _yellow "IP及解锁状态检测"
        echo "1. ChatGPT 解锁状态检测"
        echo "2. Lmc999 流媒体解锁测试 (最常用)"
        echo "3. Yeahwu 流媒体解锁检测"
        echo "4. Xykt 流媒体解锁检测 (原生检测)"
        echo "5. Xykt IP质量体检"
        echo "6. 1-stream 流媒体解锁检测 (准确度最高)"
        short_line
        _yellow "网络线路测速"
        echo "12. Besttrace 三网回程延迟路由测试"
        echo "13. Mtr trace 三网回程线路测试"
        echo "14. Superspeed 三网测速"
        echo "15. Nxtrace 快速回程测试脚本 (北上广)"
        echo "16. Nxtrace 指定IP回程测试脚本"
        echo "17. Oneclickvirt 三网线路测试"
        echo "18. i-abc 多功能测速脚本"
        echo "19. Chennhaoo 三网回程TCP路由详细测试"
        short_line
        _yellow "硬件性能测试"
        echo "25. Yabs 性能测试"
        echo "26. Icu/gb5 CPU性能测试脚本"
        short_line
        _yellow "综合性测试"
        echo "30. Bench 性能测试"
        echo "31. spiritLHLS 融合怪测评"
        echo "32. LemonBench 综合测试"
        echo "33. NodeBench VPS聚合测试"
        short_line
        echo "0. 返回菜单"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1) clear_screen ; bash <(curl -sL ${github_Proxy}https://github.com/missuo/OpenAI-Checker/raw/main/openai.sh) ;;
            2) clear_screen ; bash <(curl -sL ${github_Proxy}https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/check.sh) ;;
            3) clear_screen ; bash <(curl -sL ${github_Proxy}https://github.com/yeahwu/check/raw/main/check.sh) ;;
            4) clear_screen ; bash <(curl -sL ${github_Proxy}https://raw.githubusercontent.com/xykt/RegionRestrictionCheck/main/check.sh) ;; # 原生检测脚本
            5) clear_screen ; bash <(curl -Ls ${github_Proxy}https://raw.githubusercontent.com/xykt/IPQuality/main/ip.sh) ;;
            6) clear_screen ; bash <(curl -L -s ${github_Proxy}https://github.com/1-stream/RegionRestrictionCheck/raw/main/check.sh) ;;
            12) clear_screen ; bash <(curl -sL ${github_Proxy}https://github.com/honeok/cross/raw/master/bestTrace.sh) ;;
            13) clear_screen ; bash <(curl -sL ${github_Proxy}https://raw.githubusercontent.com/zhucaidan/mtr_trace/main/mtr_trace.sh) ;;
            14) clear_screen ; bash <(curl -Lso- ${github_Proxy}https://raw.githubusercontent.com/uxh/superspeed/master/superspeed.sh) ;;
            15) clear_screen ; curl -sL nxtrace.org/nt | bash ; nexttrace --fast-trace --tcp ;; # 北上广(电信+联通+移动+教育网)IPv4 / IPv6 ICMP快速测试, 使用TCP SYN 而非ICMP进行测试
            16)
                clear_screen
                echo "Nxtrace指定IP回程测试脚本"
                echo "可参考的IP列表"
                short_line
                echo "北京电信: 219.141.140.10"
                echo "北京联通: 202.106.195.68"
                echo "北京移动: 221.179.155.161"
                echo "上海电信: 202.96.209.133"
                echo "上海联通: 210.22.97.1"
                echo "上海移动: 211.136.112.200"
                echo "广州电信: 58.60.188.222"
                echo "广州联通: 210.21.196.6"
                echo "广州移动: 120.196.165.24"
                echo "成都电信: 61.139.2.69"
                echo "成都联通: 119.6.6.6"
                echo "成都移动: 211.137.96.205"
                short_line

                echo -n -e "${yellow}输入一个指定IP: ${white}"
                read -r choice
                curl -sL nxtrace.org/nt | bash
                nexttrace -M "$choice"
                ;;
            17) clear_screen ; bash <(curl -sL ${github_Proxy}https://github.com/honeok/cross/raw/master/backtrace.sh) -d ;;
            18) clear_screen ; bash <(curl -sL ${github_Proxy}https://raw.githubusercontent.com/i-abc/Speedtest/main/speedtest.sh) ;;
            19) clear_screen ; curl -fskLz -O ${github_Proxy}https://raw.githubusercontent.com/Chennhaoo/Shell_Bash/master/AutoTrace.sh && chmod +x AutoTrace.sh && bash AutoTrace.sh ;;
            25) clear_screen ; check_swap; curl -sL ${github_Proxy}https://github.com/masonr/yet-another-bench-script/raw/master/yabs.sh | bash -s -- -i -5 ;;
            26) clear_screen ; check_swap ;bash <(curl -sL ${github_Proxy}https://raw.githubusercontent.com/i-abc/GB5/main/gb5-test.sh) ;;
            30) clear_screen ; bash <(curl -Lso- ${github_Proxy}https://github.com/teddysun/across/raw/master/bench.sh) ;;
            31) clear_screen ; curl -sL ${github_Proxy}https://github.com/spiritLHLS/ecs/raw/main/ecs.sh -o ecs.sh && chmod +x ecs.sh && bash ecs.sh ;;
            32) clear_screen ; curl -fsL ${github_Proxy}https://raw.githubusercontent.com/LemonBench/LemonBench/main/LemonBench.sh | bash -s -- --fast ;;
            33) clear_screen ; bash <(curl -sL ${github_Proxy}https://raw.githubusercontent.com/LloydAsp/NodeBench/main/NodeBench.sh) ;;
            0) menu ;;
            *) echo "$(_red '无效选项, 请重新输入')" ;;
        esac
        end_of
    done
}

## 节点搭建

node_create() {
    local choice

    if [ "$loc" = "CN" ];then
        clear_screen
        _err_msg "$(_red '时刻铭记上网三要素: 不评政治、不谈宗教、不碰黄賭毒, 龙的传人需自律.')"
        _err_msg "$(_red '本功能所提供的内容已触犯你的IP所在地相关法律法规请绕行!')"
        end_of
        menu # 返回主菜单
    fi

    while true; do
        clear_screen
        echo "▶ 节点搭建脚本合集"
        short_line
        _yellow "Sing-box多合一脚本/Argo隧道"
        echo "1. Fscarmen Sing-box"
        echo "3. FranzKafkaYu Sing-box"
        echo "5. 233boy Sing-box"
        echo "6. 233boy V2Ray"
        echo "7. Fscarmen ArgoX"
        echo "8. WL一键Argo哪吒脚本"
        echo "9. Fscarmen Argo+Sing-box"
        echo "10. 甬哥Sing-box一键四协议共存"
        echo "11. vveg26 Reality Hysteria2二合一"
        short_line
        _yellow "单协议/面板"
        echo "26. Vaxilu x-ui面板"
        echo "27. FranzKafkaYu x-ui面板"
        echo "28. Alireza0 x-ui面板"
        echo "29. MHSanaei 伊朗3x-ui面板"
        echo "30. Xeefei 中文版3x-ui面板"
        echo "31. Jonssonyan Hysteria2面板"
        echo "32. 极光面板"
        short_line
        echo "40. OpenVPN一键安装脚本"
        short_line
        _yellow "中转搭建一键脚本"
        echo "50. Multi EasyGost"
        echo "51. EZgost一键脚本 (EasyGost改版)"
        echo "52. Realm一键安装脚本"
        short_line
        echo "0. 返回主菜单"
        short_line

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/fscarmen/sing-box/main/sing-box.sh) -c ;;
            3) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/FranzKafkaYu/sing-box-yes/master/install.sh) ;;
            5) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/233boy/sing-box/main/install.sh) ;;
            6) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/233boy/v2ray/master/install.sh) ;;
            7) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/fscarmen/argox/main/argox.sh) ;;
            8) clear_screen ; bash <(curl -sL https://raw.githubusercontent.com/dsadsadsss/vps-argo/main/install.sh) ;;
            9) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/fscarmen/sba/main/sba.sh) ;;
            10) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/sb.sh) ;;
            11) clear_screen ; bash <(curl -fsSL https://github.com/vveg26/sing-box-reality-hysteria2/raw/main/install.sh) ;;
            26) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/vaxilu/x-ui/master/install.sh) ;;
            27) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/FranzKafkaYu/x-ui/master/install.sh) ;;
            28) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh) ;;
            29) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh) ;;
            30) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/xeefei/3x-ui/master/install.sh) ;;
            31) clear_screen ; bash <(curl -fsSL https://raw.githubusercontent.com/jonssonyan/h-ui/main/install.sh) ;;
            32) clear_screen ; bash <(curl -fsSL https://raw.githubusercontent.com/Aurora-Admin-Panel/deploy/main/install.sh) ;;
            40) clear_screen ; curl -fskLz -O https://raw.githubusercontent.com/Nyr/openvpn-install/master/openvpn-install.sh && bash openvpn-install.sh ;;
            50) clear_screen ; curl -fskLz -O https://raw.githubusercontent.com/KANIKIG/Multi-EasyGost/master/gost.sh && chmod +x gost.sh && ./gost.sh ;;
            51) clear_screen ; curl -fskLz -O https://raw.githubusercontent.com/qqrrooty/EZgost/main/gost.sh && chmod +x gost.sh && ./gost.sh ;;
            52) clear_screen ; bash <(curl -Ls https://raw.githubusercontent.com/zhouh047/realm-oneclick-install/main/realm.sh) -i ;;
            0) menu ;;
            *) _red "无效选项, 请重新输入" ;;
        esac
        end_of
    done
}

menu() {
    local choice

    clear_screen
    while true; do
        print_logo
        echo "$(_purple '适配Ubuntu/Debian/CentOS/Alpine/Kali/Arch/RedHat/Fedora/Alma/Rocky系统')"
        echo "$(_cyan 'Author: honeok') $(_yellow "$honeok_v")"
        short_line
        echo "1.   系统信息查询"
        echo "2.   系统更新"
        echo "3.   系统清理"
        echo "4.   基础工具 ▶"
        echo "5.   BBR管理 ▶"
        echo "6.   Docker管理 ▶"
        echo "7.   WARP管理 ▶"
        echo "13.  系统工具 ▶"
        echo "14.  我的工作区 ▶"
        echo "15.  测试脚本合集 ▶"
        echo "16.  节点搭建脚本合集 ▶"
        short_line
        echo "0.   退出脚本"
        short_line
        echo ""

        reading '请输入选项并按回车键确认: ' choice

        case $choice in
            1) clear_screen; system_info ;;
            2) clear_screen; linux_update;;
            3) clear_screen; linux_clean ;;
            4) linux_tools ;;
            5) linux_bbr ;;
            6) docker_manager ;;
            7) clear_screen; warp_manager ;;
            13) linux_system_tools;;
            14) linux_workspace ;;
            15) servertest_script ;;
            16) node_create ;;
            17) oracle_script ;;
            0) _orange "Bye!" && sleep 1 && clear_screen && cleanup_exit && exit 0;;
            *) echo "$(_red '无效选项, 请重新输入')";;
        esac
        end_of
    done
}

honeok() {
    pre_check
    menu
}

honeok