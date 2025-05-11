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

WORKDIR="/DanmakuRender"
DANMAKU_CONFIG="$WORKDIR/configs"
DANMAKU_TEMP_CONFIG="/opt/configs"

if [ -d "$DANMAKU_CONFIG" ] && [ -z "$(find "$DANMAKU_CONFIG" -mindepth 1 -print -quit)" ]; then
    command cp -rf "$DANMAKU_TEMP_CONFIG"/* "$DANMAKU_CONFIG/"
fi

if [ "$#" -eq 0 ]; then
    exec python3 -u "$WORKDIR/main.py" --config "$DANMAKU_CONFIG" --skip_update
else
    exec "$@"
fi