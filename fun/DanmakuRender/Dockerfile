# Description: Dockerfile for creating a containerized solution for automated DanmakuRender video recording.
#
# Copyright (c) 2024-2025 honeok <honeok@duck.com>
#
# References:
# https://github.com/SmallPeaches/DanmakuRender
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

FROM python:3.9.20-slim-bookworm

WORKDIR /DanmakuRender

COPY . .

RUN set -ex \
        && apt-get update \
        && apt-get -y install \
            curl \
            ffmpeg \
            git \
            nodejs \
            npm \
        && chmod +x build.sh && ./build.sh \
        && python3 -m pip install --no-cache-dir -r requirements.txt \
        && install -m 755 docker-entrypoint.sh /docker-entrypoint.sh \
        && rm -f build.sh docker-entrypoint.sh \
        && rm -rf configs_temp \
        && mkdir -p configs_temp \
        && apt-get -y remove --purge \
            curl \
            git \
        && apt-get clean \
        && cp -rf configs/* configs_temp/ \
        && rm -rf /var/lib/apt/lists/* /var/log/* /tmp/*

ENTRYPOINT [ "/docker-entrypoint.sh" ]