# Description: Self-compiled NGINX with Brotli and Zstandard compression
#
# Copyright (C) 2025 honeok <honeok@duck.com>
#
# References:
# https://github.com/google/ngx_brotli
# https://github.com/facebook/zstd
# https://github.com/kejilion/docker
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

FROM alpine:latest AS builder

# Docker Build Arguments
ARG NGX_LVER
ARG ZSTD_LVER
ARG NGX_J="4"

RUN set -ex \
        && apk update && apk upgrade \
        && apk add --no-cache --virtual .build-deps \
            automake \
            autoconf \
            brotli-dev \
            build-base \
            curl \
            git \
            libtool \
            linux-headers \
            openssl-dev \
            pcre-dev \
            pkgconfig \
            zlib-dev \
        && cd /tmp \
        && curl -fskL "https://nginx.org/download/nginx-${NGX_LVER}.tar.gz" -o nginx-${NGX_LVER}.tar.gz \
        && tar -zxf nginx-${NGX_LVER}.tar.gz \
        && git clone --recurse-submodules -j8 "https://github.com/google/ngx_brotli" \
        && curl -fskL "https://github.com/facebook/zstd/releases/download/v${ZSTD_LVER}/zstd-${ZSTD_LVER}.tar.gz" -o zstd-${ZSTD_LVER}.tar.gz \
        && tar -xzf zstd-${ZSTD_LVER}.tar.gz \
        && cd zstd-${ZSTD_LVER} \
        && make clean \
        && CFLAGS="-fPIC" make -j${NGX_J} \
        && make -j${NGX_J} install \
        && cd /tmp \
        && git clone --depth=10 "https://github.com/tokers/zstd-nginx-module.git" \
        && cd nginx-${NGX_LVER} \
        && ./configure --with-compat \
            --add-dynamic-module=../ngx_brotli \
            --add-dynamic-module=../zstd-nginx-module \
        && make -j${NGX_J} modules \
        && apk del .build-deps \
        && rm -rf /var/cache/apk/*

FROM nginx:alpine

ARG NGX_LVER

COPY --from=builder /tmp/nginx-${NGX_LVER}/objs/*.so /etc/nginx/modules/

COPY html /usr/share/nginx/html

RUN set -ex \
        && apk update && apk upgrade \
        && apk add --no-cache \
            pcre \
        && rm -rf /var/cache/apk/*