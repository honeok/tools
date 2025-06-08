#!/bin/bash
#
# Description: This script is used to set the upstream repository commit user.
#
# Copyright (c) 2025 honeok <honeok@disroot.org>
#
# SPDX-License-Identifier: MIT

set -e

REPOSITORY="$(pwd | awk -F'/' '{print $NF}')"
CODE_PLATFORM="$(pwd | awk -F'/' '{print $(NF-1)}')"
separator() { printf "%-20s\n" "-" | sed 's/\s/-/g'; }

case "$CODE_PLATFORM" in
    github*) WORK_PLATFORM="github" ;;
    gitlab*) WORK_PLATFORM="gitlab" ;;
    *) echo "Error: Unknown platform."; exit 1 ;;
esac

while true; do
    separator
    echo " 1. honeok"
    echo " 2. havario"
    separator
    read -rep "Please enter user: " USER
    case "$USER" in
        1)
            git config user.name honeok
            [ "$WORK_PLATFORM" = "github" ] && git config user.email "100125733+honeok@users.noreply.github.com"
            git remote set-url origin "git@${WORK_PLATFORM}-${USER}:${USER}/${REPOSITORY}.git"
            break
        ;;
        2)
            git config user.name havario
            [ "$WORK_PLATFORM" = "github" ] && git config user.email "157877551+havario@users.noreply.github.com"
            git remote set-url origin "git@${WORK_PLATFORM}-${USER}:${USER}/${REPOSITORY}.git"
            break
        ;;
        *)
            echo "Error: Unknown User"
        ;;
    esac

    git config --get user.name
    git config --get user.email
done