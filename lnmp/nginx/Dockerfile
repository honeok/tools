# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Description: This dockerfile is used to add third-party modules to nginx and recompile the nginx web server.
# Copyright (c) 2024-2026 honeok <i@honeok.com>

ARG NGINX_VERSION=""

FROM alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 AS builder

ARG NGINX_VERSION=""
ARG GEOIP2_VERSION=""
ARG ZSTD_VERSION=""
ARG HEADERS_MORE_VERSION=""

ARG NGX_DYNAMIC_MODULE_ARGS="\
    --with-compat \
    --with-stream \
    --add-dynamic-module=../ngx_brotli \
    --add-dynamic-module=../zstd-nginx-module \
    --add-dynamic-module=../headers-more-nginx-module-${HEADERS_MORE_VERSION} \
    --add-dynamic-module=../ngx_http_geoip2_module-${GEOIP2_VERSION} \
    "

RUN set -ex \
    && apk add --update --no-cache --virtual .build-deps \
        brotli-dev \
        build-base \
        curl \
        git \
        lz4-dev \
        libmaxminddb-dev \
        openssl-dev \
        pcre2-dev \
        xz-dev \
        zlib-dev \
    && cd /tmp \
    && curl -Ls https://github.com/nginx/nginx/releases/download/release-${NGINX_VERSION}/nginx-${NGINX_VERSION}.tar.gz -o nginx-${NGINX_VERSION}.tar.gz \
    && tar fxz nginx-${NGINX_VERSION}.tar.gz \
    && git clone --recurse-submodules -j8 https://github.com/google/ngx_brotli \
    && curl -Ls https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz -o zstd-${ZSTD_VERSION}.tar.gz \
    && tar fxz zstd-${ZSTD_VERSION}.tar.gz \
    && cd zstd-${ZSTD_VERSION} \
    && make clean \
    && CFLAGS="-fPIC" make -j$(getconf _NPROCESSORS_ONLN) \
    && make -j$(getconf _NPROCESSORS_ONLN) install \
    && cd /tmp \
    && git clone --depth=10 https://github.com/tokers/zstd-nginx-module.git \
    && curl -Ls https://github.com/openresty/headers-more-nginx-module/archive/v${HEADERS_MORE_VERSION}.tar.gz -o headers-more-${HEADERS_MORE_VERSION}.tar.gz \
    && tar fxz headers-more-${HEADERS_MORE_VERSION}.tar.gz \
    && curl -Ls https://github.com/leev/ngx_http_geoip2_module/archive/${GEOIP2_VERSION}.tar.gz -o geoip2-${GEOIP2_VERSION}.tar.gz \
    && tar fxz geoip2-${GEOIP2_VERSION}.tar.gz \
    && cd nginx-${NGINX_VERSION} \
    && eval ./configure ${NGX_DYNAMIC_MODULE_ARGS} \
    && make modules \
    && strip --strip-unneeded objs/*.so \
    && apk del --no-network .build-deps \
    && rm -rf /var/cache/apk/*

FROM nginx:${NGINX_VERSION}-alpine AS dist

LABEL org.opencontainers.image.authors="honeok <i@honeok.com>"

ARG NGINX_VERSION=""

COPY --from=builder /tmp/nginx-${NGINX_VERSION}/objs/*.so /usr/lib/nginx/modules/

RUN set -ex \
    && find /usr/lib/nginx/modules/ -type f -name '*-debug.so' -delete \
    && runDeps="$( \
        scanelf --needed --nobanner --format '%n#p' \
            /usr/sbin/nginx \
            /usr/lib/nginx/modules/*.so \
        | tr ',' '\n' \
        | sort -u \
        | awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' \
    )" \
    && apk add --no-cache --virtual .runDeps ${runDeps}
