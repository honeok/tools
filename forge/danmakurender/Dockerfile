# SPDX-License-Identifier: Apache-2.0
#
# Description: The dockerfile is used for containerizing danmakurender, providing real time recording and rendering of live streams.
# Copyright (c) 2024-2025 honeok <i@honeok.com>

FROM python:3.9-slim-bookworm AS dist
LABEL maintainer="honeok <i@honeok.com>"
ARG DANMAKU_RUN_DEPS="\
    curl \
    ffmpeg \
    nodejs \
    npm \
    tzdata \
    "
ARG DANMAKU_BUILD_DEPS="\
    build-essential \
    git \
    xz-utils \
    "
ARG DANMAKU_TAG=""
ARG BILIUP_VERSION=""
WORKDIR /app
COPY docker-entrypoint.sh /
RUN set -ex \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ${DANMAKU_RUN_DEPS} \
        ${DANMAKU_BUILD_DEPS} \
    && git clone --depth=1 --branch ${DANMAKU_TAG} https://github.com/SmallPeaches/DanmakuRender.git . \
    && python3 -m pip install --no-cache-dir -r requirements.txt --root-user-action=ignore \
    && python3 -m pip install --no-cache-dir quickjs --root-user-action=ignore \
    && case "$(uname -m)" in \
        amd64|x86_64) \
            OS_ARCH="x86_64" \
        ;; \
        arm64|aarch64) \
            OS_ARCH="aarch64" \
        ;; \
    esac \
    && curl -Ls https://github.com/biliup/biliup-rs/releases/download/v${BILIUP_VERSION}/biliupR-v${BILIUP_VERSION}-${OS_ARCH}-linux.tar.xz | tar xJf - -C tools/ --strip 1 \
    && chmod +x /docker-entrypoint.sh \
    && apt-get purge -y --auto-remove ${DANMAKU_BUILD_DEPS} \
    && rm -rf /var/lib/apt/lists/* /tmp/* docs/ Dockerfile README.md requirements.txt
ENV TZ=Asia/Shanghai
VOLUME ["/app"]
ENTRYPOINT ["/docker-entrypoint.sh"]
