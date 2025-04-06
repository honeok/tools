#!/usr/bin/env bash
#
# Description: configures a swap partition on a Linux server running kvm or openvz virtualization.
#
# Copyright (c) 2025 honeok <honeok@duck.com> All rights reserved.
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

# shellcheck disable=all

red='\033[91m'
green='\033[92m'
yellow='\033[93m'
cyan='\033[96m'
white='\033[0m'
_red() { printf "$red%s$white" "$*"; }
_green() { printf "$green%s$white" "$*"; }
_yellow() { printf "$yellow%s$white" "$*"; }
_cyan() { printf "$cyan%s$white" "$*"; }

_err_msg() { printf "\033[41m\033[1mError$white %s\n" "$*"; }
_suc_msg() { printf "\033[42m\033[1mSuccess$white %s\n" "$*"; }

reading() { read -rp "$(_yellow "$1")" "$2"; }

SCRIPT="addswap.sh"
DEST_DIR="/tmp"
CRON_FILE="/etc/crontab"

pre_check() {
    local utf8_locale

    utf8_locale=$(locale -a 2>/dev/null | grep -iE -m 1 "UTF-8|utf8")
    if [ -z "$utf8_locale" ]; then
        _err_msg "$(_red 'No UTF-8 locale found!')" && exit 1
    else
        export LC_ALL="$utf8_locale"
        export LANG="$utf8_locale"
        export LANGUAGE="$utf8_locale"
    fi

    if [ "$(id -ru)" -ne 0 ] || [ "$EUID" -ne 0 ]; then
        _err_msg "$(_red 'This script must be run as root!')" && exit 1
    fi
    if [ "$(ps -p $$ -o comm=)" != "bash" ] || readlink /proc/$$/exe | grep -q "dash"; then
        _err_msg "$(_red 'This script needs to be run with bash, not sh!')" && exit 1
    fi
}

# 检查架构
check_virt() {
  virtcheck=$(systemd-detect-virt)
  case "$virtcheck" in
  kvm) VIRT='kvm' ;;
  openvz) VIRT='openvz' ;;
  *) VIRT='kvm' ;;
  esac
}

delete_cron_entry() {
  if grep -q "$1" "$CRON_FILE"; then
    sed -i "\|$1|d" "$CRON_FILE"
  fi
}

set_swappiness() {
  _blue "Smaller values indicate more aggressive use of physical memory, and a setting of 1 is recommended."
  _blue "数值越小表示越积极使用物理内存，推荐设置为1。"
  while true; do
    _green "Please enter the desired swappiness value (1-100):"
    _green "请输入期望的swappiness值 (1-100)："
    reading "Swappiness value (1-100): " swappiness
    if [[ $swappiness =~ ^[0-9]+$ ]] && [ $swappiness -ge 1 ] && [ $swappiness -le 100 ]; then
      echo $swappiness > /proc/sys/vm/swappiness
      _green "Swappiness is set to $swappiness."
      _green "swappiness已设置为 $swappiness。"
      if grep -q "^vm.swappiness=" /etc/sysctl.conf; then
        sed -i "s/^vm.swappiness=.*/vm.swappiness=$swappiness/" /etc/sysctl.conf
        _green "Updated vm.swappiness in /etc/sysctl.conf to $swappiness."
      else
        echo "vm.swappiness=$swappiness" >> /etc/sysctl.conf
        _green "Added vm.swappiness=$swappiness to /etc/sysctl.conf."
      fi
      sysctl -p
      _green "Sysctl configuration reloaded."
      break
    else
      _red "Invalid input. Please enter a number between 1 and 100."
      _red "输入无效，请输入1到100之间的数字。"
    fi
  done
}

check_swappiness() {
  swappiness=$(cat /proc/sys/vm/swappiness)
  _blue "Current swappiness value is $swappiness."
  _blue "当前的swappiness值为 $swappiness。"
}
del_swap() {
  if [ $VIRT = "openvz" ]; then
    echo 'Start deleting SWAP space ......'
    SWAP=0
    NEW="$((SWAP * 1024))"
    TEMP="${NEW//?/ }"
    OLD="${TEMP:1}0"
    umount /proc/meminfo 2>/dev/null
    sed "/^Swap\(Total\|Free\):/s,$OLD,$NEW," /proc/meminfo >/etc/fake_meminfo
    mount --bind /etc/fake_meminfo /proc/meminfo
    delete_cron_entry "$0"
    delete_cron_entry "$DEST_DIR/$SCRIPT -C"
    echo -e "${green}swap删除成功，并查看信息：${white}"
    free -m
  else
    #检查是否存在swapfile
    grep -q "swapfile" /etc/fstab

    #如果存在就将其移除
    if [ $? -eq 0 ]; then
      echo -e "${green}swapfile已发现，正在将其移除...${white}"
      sed -i '/swapfile/d' /etc/fstab
      echo "3" >/proc/sys/vm/drop_caches
      swapoff -a
      rm -f /swapfile
      echo -e "${green}swap已删除！${white}"
    else
      echo -e "${red}swapfile未发现，swap删除失败！${white}"
    fi
  fi
}

add_swap() {
  _green "Please enter the desired amount of swap to add, recommended to be twice the size of the memory!"
  _green "请输入需要添加的swap，建议为内存的2倍！"
  _green "Please enter the swap value in megabytes (MB) (leave blank and press Enter for default, which is twice the memory):"
  reading "请输入swap数值，以MB计算(留空回车则默认为内存的2倍):" SWAP
  if [ -z "$SWAP" ]; then
    total_memory=$(free -m | awk '/^Mem:/{print $2}')
    SWAP=$((total_memory * 2))
  fi
  CRON_ENTRY="@reboot root $DEST_DIR/$SCRIPT -C $SWAP"
  echo 'Start adding SWAP space ......'
  if [ $VIRT = "openvz" ]; then
    NEW="$((SWAP * 1024))"
    TEMP="${NEW//?/ }"
    OLD="${TEMP:1}0"
    umount /proc/meminfo 2>/dev/null
    sed "/^Swap\(Total\|Free\):/s,$OLD,$NEW," /proc/meminfo >/etc/fake_meminfo
    mount --bind /etc/fake_meminfo /proc/meminfo
    sed -i "/$0/d" /etc/crontab | echo "no swap shell in crontab"
    cp "$SCRIPT" "$DEST_DIR/$SCRIPT"
    delete_cron_entry "$0"
    delete_cron_entry "$DEST_DIR/$SCRIPT -C"
    echo "$CRON_ENTRY" >>"$CRON_FILE"
    _green "swap creation successful, and view the information:"
    _green "swap创建成功，并查看信息："
    free -m
  else
    #检查是否存在swapfile
    grep -q "swapfile" /etc/fstab
    #如果不存在将为其创建swap
    if [ $? -ne 0 ]; then
      _green "Swapfile not found, creating a swapfile for it."
      _green "swapfile未发现，正在为其创建swapfile"
      fallocate -l ${SWAP}M /swapfile
      chmod 600 /swapfile
      mkswap /swapfile
      swapon /swapfile
      echo '/swapfile none swap defaults 0 0' >>/etc/fstab
      _green "swap creation successful, and view the information:"
      _green "swap创建成功，并查看信息："
      cat /proc/swaps
      cat /proc/meminfo | grep Swap
    else
      _red "swapfile already exists, swap configuration failed. Please run the script to remove the existing swap and then reconfigure."
      _red "swapfile已存在，swap设置失败，请先运行脚本删除swap后重新设置！"
    fi
  fi
}

# 开始菜单
main() {
  pre_check
  check_virt
  clear
  free -m
  check_swappiness
  echo -e "—————————————————————————————————————————————————————————————"
  _green "Linux VPS one click add/remove swap script ${white}"
  _green "1, Add swap${white}"
  _green "2, Remove swap${white}"
  _green "3, Set swappiness value${white}"
  echo -e "—————————————————————————————————————————————————————————————"
  while true; do
    _green "Please enter a number"
    reading "请输入数字 [1-3]:" num
    case "$num" in
    1)
      add_swap
      break
      ;;
    2)
      del_swap
      break
      ;;
    3)
      set_swappiness
      break
      ;;
    *)
      echo "输入错误，请重新输入"
      ;;
    esac
  done
}

main