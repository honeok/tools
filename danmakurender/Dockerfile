# Description: creating a containerized solution for automated DanmakuRender video recording.
#
# Copyright (c) 2024-2025 honeok <honeok@duck.com>
#
# References:
# https://github.com/SmallPeaches/DanmakuRender
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

FROM python:3.9.22-slim-bookworm

WORKDIR /DanmakuRender

COPY build.sh .
COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN set -ex \
        && apt-get update \
        && apt-get -y install \
            ffmpeg \
            git \
            nodejs \
            npm \
        && chmod +x /docker-entrypoint.sh build.sh \
        && ./build.sh && rm -f build.sh \
        && python3 -m pip install --no-cache-dir -r requirements.txt \
        && python3 -m pip install --no-cache-dir quickjs \
        && apt-get -y remove --purge \
            git \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/* /var/log/* /tmp/*

ENTRYPOINT [ "/docker-entrypoint.sh" ]