#!/usr/bin/env sh
#
# Copyright (c) 2025 honeok <honeok@duck.com>
#
# References:
# https://github.com/SmallPeaches/DanmakuRender
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

work_dir="/DanmakuRender"
danmaku_config_dir="$work_dir/configs"
danmaku_config_dir_temp="$work_dir/configs_temp"

if [ -d "$danmaku_config_dir" ] && [ -z "$(find "$danmaku_config_dir" -mindepth 1 -print -quit)" ]; then
    command cp -rf "$danmaku_config_dir_temp"/* "$danmaku_config_dir/"
fi

if [ "$#" -eq 0 ]; then
    exec python3 -u "$work_dir/main.py" --config "$danmaku_config_dir" --skip_update
else
    exec "$@"
fi