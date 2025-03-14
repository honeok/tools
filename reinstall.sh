#!/usr/bin/env bash
#
# Description: Integrated system reinstallation script, based on leitbogioro and bin456789's projects.
#
# Copyright (C) 2025 honeok <honeok@duck.com>
#
# Acknowledgments:
# https://github.com/leitbogioro
# https://github.com/bin456789
# 
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

red='\033[91m'
green='\033[92m'
yellow='\033[93m'
cyan='\033[96m'
white='\033[0m'
_red() { echo -e "${red}$*${white}"; }
_green() { echo -e "${green}$*${white}"; }
_yellow() { echo -e "${yellow}$*${white}"; }
_cyan() { echo -e "${cyan}$*${white}"; }

reading() { read -rep "$(_yellow "$1")" "$2"; }
separator() { printf "%-20s\n" "-" | sed 's/\s/-/g'; }

# 各变量默认值
github_Proxy='https://goppx.com/'
os_info=$(grep "^PRETTY_NAME=" /etc/*-release | cut -d '"' -f 2 | sed 's/ (.*)//')

# 安全清屏
clear_screen() {
    if [ -t 1 ]; then
        tput clear 2>/dev/null || echo -e "\033[2J\033[H" || clear
    fi
}

pre_check() {
    if [ "$(id -ru)" -ne "0" ] || [ "$EUID" -ne "0" ]; then
        _err_msg "$(_red '此脚本必须以root用户权限运行!')" && exit 1
    fi
    if [ "$(ps -p $$ -o comm=)" != "bash" ] || readlink /proc/$$/exe | grep -q "dash"; then
        _err_msg "$(_red '此脚本必须使用bash运行, 而非sh!')" && exit 1
    fi
    if [ "$(curl -fskL -m 3 -4 'https://www.qualcomm.cn/cdn-cgi/trace' | grep -i '^loc=' | cut -d'=' -f2 | xargs)" != 'CN' ]; then
        github_Proxy=''
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

reinstall_system() {
    local choice 

    local current_sshport
    current_sshport=$(grep -E '^[^#]*Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}' | head -n 1)
    [ -z "$current_sshport" ] && current_sshport=22

    script_MollyLau() { curl -fskL -O "${github_Proxy}https://github.com/leitbogioro/Tools/raw/master/Linux_reinstall/InstallNET.sh" && chmod +x InstallNET.sh; }
    script_bin456789() { curl -fskL -O "${github_Proxy}https://github.com/bin456789/reinstall/raw/main/reinstall.sh" && chmod +x reinstall.sh; }

    reinstall_linux_MollyLau() {
        echo "重装后初始用户名: $(_yellow 'root') 初始密码: $(_yellow 'LeitboGi0ro') 初始端口: $(_yellow "$current_sshport")"
        _yellow "按任意键继续"
        read -n 1 -s -r -p ""
        script_MollyLau
        check_swap
    }

    reinstall_win_MollyLau() {
        echo "重装后初始用户名: $(_yellow 'Administrator') 初始密码: $(_yellow 'Teddysun.com') 初始端口: $(_yellow '3389')"
        _yellow "按任意键继续"
        read -n 1 -s -r -p ""
        script_MollyLau
        check_swap
    }

    reinstall_linux_bin456789() {
        echo "重装后初始用户名: $(_yellow 'root') 初始密码: $(_yellow '123@@@') 初始端口: $(_yellow '22')"
        _yellow "按任意键继续"
        read -n 1 -s -r -p ""
        script_bin456789
        check_swap
    }

    reinstall_win_bin456789() {
        echo "重装后初始用户名: $(_yellow 'Administrator') 初始密码: $(_yellow '123@@@') 初始端口: $(_yellow '3389')"
        _yellow "按任意键继续"
        read -n 1 -s -r -p ""
        script_bin456789
        check_swap
    }

    while true; do
        clear_screen
        echo "$(_red '注意: ')重装有风险失联, 不放心者慎用重装预计花费15分钟, 请提前备份数据!"
        _cyan "感谢MollyLau大佬和bin456789大佬的脚本支持!"
        separator
        _yellow "当前操作系统: $os_info"
        separator
        echo "1. Debian 12                  2. Debian 11"
        echo "3. Debian 10                  4. Debian 9"
        separator
        echo "11. Ubuntu 24.04              12. Ubuntu 22.04"
        echo "13. Ubuntu 20.04              14. Ubuntu 18.04"
        separator
        echo "21. Rocky Linux 9             22. Rocky Linux 8"
        echo "23. Alma Linux 9              24. Alma Linux 8"
        echo "25. Oracle Linux 9            26. Oracle Linux 8"
        echo "27. Fedora Linux 41           28. Fedora Linux 40"
        echo "29. CentOS 10                 30. CentOS 7"
        separator
        echo "31. Alpine Linux              32. Arch Linux"
        echo "33. Kali Linux                34. openEuler"
        echo "35. openSUSE Tumbleweed       36. gentoo"
        separator
        echo "41. Windows 11                42. Windows 10"
        echo "43. Windows 7                 44. Windows Server 2022"
        echo "45. Windows Server 2019       46. Windows Server 2016"
        echo "47. Windows 11 ARM"
        separator

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
            *)
                break
            ;;
        esac
    done
}

reinstall() {
    pre_check
    reinstall_system
}

reinstall