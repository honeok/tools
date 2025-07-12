# Description: This dockerfile is used to custom compile nginx with brotli and zstandard compression.
#
# Copyright (c) 2024-2025 honeok <i@honeok.com>
#
# Thanks: kejilion <lion12776@outlook.com>
#
# SPDX-License-Identifier: Apache-2.0

# Second stage image name
ARG NGX_VERSION=""

FROM alpine:latest AS builder

LABEL maintainer="honeok <i@honeok.com>"

ARG NGX_VERSION=""
ARG ZSTD_VERSION=""

RUN set -ex \
    && apk add --update --no-cache --virtual .build-deps \
        brotli-dev \
        build-base \
        curl \
        git \
        make \
        pcre2-dev \
    && cd /tmp \
    && curl -Ls https://nginx.org/download/nginx-${NGX_VERSION}.tar.gz -o nginx-${NGX_VERSION}.tar.gz \
    && tar fxz nginx-${NGX_VERSION}.tar.gz \
    && git clone --recurse-submodules -j8 https://github.com/google/ngx_brotli \
    && curl -Ls https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz -o zstd-${ZSTD_VERSION}.tar.gz \
    && tar fxz zstd-${ZSTD_VERSION}.tar.gz \
    && cd zstd-${ZSTD_VERSION} \
    && make clean \
    && CFLAGS="-fPIC" make -j$(getconf _NPROCESSORS_ONLN) \
    && make -j$(getconf _NPROCESSORS_ONLN) install \
    && cd /tmp \
    && git clone --depth=10 https://github.com/tokers/zstd-nginx-module.git \
    && cd nginx-${NGX_VERSION} \
    && ./configure --with-compat \
        --add-dynamic-module=../ngx_brotli \
        --add-dynamic-module=../zstd-nginx-module \
    && make modules \
    && apk del .build-deps \
    && rm -rf /var/cache/apk/*

FROM nginx:${NGX_VERSION}-alpine AS dist

LABEL maintainer="honeok <i@honeok.com>"

ARG NGX_VERSION=""

COPY --from=builder /tmp/nginx-${NGX_VERSION}/objs/*.so /usr/lib/nginx/modules
COPY html /usr/share/nginx/html

RUN set -ex \
    && apk add --update --no-cache --virtual .run-deps \
        binutils \
    && strip /usr/lib/nginx/modules/ngx_http_brotli_*.so \
    && strip /usr/lib/nginx/modules/ngx_http_zstd_*.so \
    && apk del --no-network .run-deps \
    && curl -Ls https://cdn.skyimg.net/up/2025/5/29/d655ae75.webp -o /usr/share/nginx/html/favicon.ico \
    && rm -rf /var/cache/apk/*