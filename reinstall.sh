#!/usr/bin/env bash
#
# Description: Integrated system reinstallation script, based on bin456789's projects.
#
# Copyright (C) 2025 honeok <honeok@duck.com>
#
# Acknowledgments:
# https://github.com/bin456789
# 
# Licensed under the GNU General Public License, version 3 or later.
# This program is distributed WITHOUT ANY WARRANTY.
# See <https://www.gnu.org/licenses/gpl-3.0.html>.

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
GITHUB_PROXY='https://goppx.com/'
OS_INFO=$(grep "^PRETTY_NAME=" /etc/*-release | cut -d '"' -f 2 | sed 's/ (.*)//')

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
        unset GITHUB_PROXY
    fi
}

reinstall_system() {
    local down_url fixed_par choice
    down_url="curl -fskL -O "${GITHUB_PROXY}https://github.com/bin456789/reinstall/raw/main/reinstall.sh" && chmod +x reinstall.sh"
    fixed_par='--password 123@@@ --ssh-port 22'

    reinstall_linux() {
        echo "重装后初始用户名: $(_yellow 'root') 初始密码: $(_yellow '123@@@') 初始端口: $(_yellow '22')"
        _yellow "按任意键继续"
        read -n 1 -s -r -p ""
        eval "$down_url"
    }

    while true; do
        clear_screen
        echo "$(_red '注意: ')重装有风险失联, 不放心者慎用重装预计花费15分钟, 请提前备份数据!"
        _cyan "感谢bin456789大佬的脚本支持!"
        separator
        _yellow "当前操作系统: $OS_INFO"
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
        echo "29. CentOS 10                 30. CentOS 9"
        separator
        echo "31. Alpine Linux              32. Arch Linux"
        echo "33. Kali Linux                34. openEuler"
        echo "35. openSUSE Tumbleweed       36. gentoo"
        separator

        reading '请输入选项并按回车键确认: ' choice

        case "$choice" in
            1)
                reinstall_linux
                bash reinstall.sh debian 12 "$fixed_par"
                reboot
                exit
            ;;
            2)
                reinstall_linux
                bash reinstall.sh debian 11 "$fixed_par"
                reboot
                exit
            ;;
            3)
                reinstall_linux
                bash reinstall.sh debian 10 "$fixed_par"
                reboot
                exit
            ;;
            4)
                reinstall_linux
                bash reinstall.sh debian 9 "$fixed_par"
                reboot
                exit
            ;;
            11)
                reinstall_linux
                bash reinstall.sh ubuntu 24.04 "$fixed_par"
                reboot
                exit
            ;;
            12)
                reinstall_linux
                bash reinstall.sh ubuntu 22.04 "$fixed_par"
                reboot
                exit
            ;;
            13)
                reinstall_linux
                bash reinstall.sh ubuntu 20.04 "$fixed_par"
                reboot
                exit
            ;;
            14)
                reinstall_linux
                bash reinstall.sh ubuntu 18.04 "$fixed_par"
                reboot
                exit
            ;;
            21)
                reinstall_linux
                bash reinstall.sh rocky 9 "$fixed_par"
                reboot
                exit
            ;;
            22)
                reinstall_linux
                bash reinstall.sh rocky 8 "$fixed_par"
                reboot
                exit
            ;;
            23)
                reinstall_linux
                bash reinstall.sh almalinux 9 "$fixed_par"
                reboot
                exit
            ;;
            24)
                reinstall_linux
                bash reinstall.sh almalinux 8 "$fixed_par"
                reboot
                exit
            ;;
            25)
                reinstall_linux
                bash reinstall.sh oracle 9 "$fixed_par"
                reboot
                exit
            ;;
            26)
                reinstall_linux
                bash reinstall.sh oracle 8 "$fixed_par"
                reboot
                exit
            ;;
            27)
                reinstall_linux
                bash reinstall.sh fedora 41 "$fixed_par"
                reboot
                exit
            ;;
            28)
                reinstall_linux
                bash reinstall.sh fedora 40 "$fixed_par"
                reboot
                exit
            ;;
            29)
                reinstall_linux
                bash reinstall.sh centos 10 "$fixed_par"
                reboot
                exit
            ;;
            30)
                reinstall_linux
                bash reinstall.sh centos 9 "$fixed_par"
                reboot
                exit
            ;;
            31)
                reinstall_linux
                bash reinstall.sh alpine "$fixed_par"
                reboot
                exit
            ;;
            32)
                reinstall_linux
                bash reinstall.sh arch "$fixed_par"
                reboot
                exit
            ;;
            33)
                reinstall_linux
                bash reinstall.sh kali "$fixed_par"
                reboot
                exit
            ;;
            34)
                reinstall_linux
                bash reinstall.sh openeuler "$fixed_par"
                reboot
                exit
            ;;
            35)
                reinstall_linux
                bash reinstall.sh opensuse "$fixed_par"
                reboot
                exit
            ;;
            36)
                reinstall_linux
                bash reinstall.sh gentoo "$fixed_par"
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