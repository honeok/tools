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

FROM python:3.9-alpine

WORKDIR /DanmakuRender

COPY build.sh .
COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN set -ex \
        && apk update && apk upgrade \
        && apk add --no-cache --virtual .build-deps \
            build-base \
            cargo \
            git \
            linux-headers \
            musl-dev \
            python3-dev \
            rust \
        && apk add --no-cache \
            ffmpeg \
            nodejs \
            npm \
            tzdata \
        && chmod +x /docker-entrypoint.sh build.sh \
        && ./build.sh && rm -f build.sh \
        && python3 -m pip install --no-cache-dir -r requirements.txt --root-user-action=ignore \
        && python3 -m pip install --no-cache-dir quickjs --root-user-action=ignore \
        && apk del .build-deps \
        && rm -rf /var/cache/apk/* /tmp/*

ENV TZ=Asia/Shanghai

ENTRYPOINT [ "/docker-entrypoint.sh" ]