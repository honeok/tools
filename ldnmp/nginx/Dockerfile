# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Description: This dockerfile is used to add third-party modules to nginx and recompile the nginx web server.
# Copyright (c) 2024-2026 honeok <i@honeok.com>

ARG NGX_VERSION=""

FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS builder

LABEL maintainer="honeok <i@honeok.com>"

ARG NGX_VERSION=""
ARG ZSTD_VERSION=""
ARG ACME_VERSION=""
ARG HEADERS_MORE_TAG=""

RUN set -ex \
    && apk add --update --no-cache --virtual .build-deps \
        brotli-dev \
        build-base \
        cargo \
        clang-dev \
        curl \
        git \
        lz4-dev \
        openssl-dev \
        pcre2-dev \
        rust \
        xz-dev \
        zlib-dev \
    && cd /tmp \
    && curl -Ls https://github.com/nginx/nginx/releases/download/release-${NGX_VERSION}/nginx-${NGX_VERSION}.tar.gz -o nginx-${NGX_VERSION}.tar.gz \
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
    && curl -Ls https://github.com/openresty/headers-more-nginx-module/archive/v${HEADERS_MORE_TAG}.tar.gz -o v${HEADERS_MORE_TAG}.tar.gz \
    && tar fxz v${HEADERS_MORE_TAG}.tar.gz \
    && curl -Ls https://github.com/nginx/nginx-acme/releases/download/v${ACME_VERSION}/nginx-acme-${ACME_VERSION}.tar.gz -o nginx-acme-${ACME_VERSION}.tar.gz \
    && tar fxz nginx-acme-${ACME_VERSION}.tar.gz \
    && cd nginx-${NGX_VERSION} \
    && ./configure \
        --with-compat \
        --with-http_ssl_module \
        --add-dynamic-module=../ngx_brotli \
        --add-dynamic-module=../zstd-nginx-module \
        --add-dynamic-module=../headers-more-nginx-module-${HEADERS_MORE_TAG} \
        --add-dynamic-module=../nginx-acme-${ACME_VERSION} \
    && make modules \
    && strip objs/*.so \
    && apk del --no-network .build-deps \
    && rm -rf /var/cache/apk/*

FROM nginx:${NGX_VERSION}-alpine AS dist

LABEL maintainer="honeok <i@honeok.com>"

ARG NGX_VERSION=""

COPY --from=builder /tmp/nginx-${NGX_VERSION}/objs/*.so /usr/lib/nginx/modules
