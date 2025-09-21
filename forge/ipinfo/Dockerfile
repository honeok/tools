# Description: This dockerfile builds a self-hosted ipinfo image for displaying client ip information without tracking or ads.
#
# Copyright (c) 2025 honeok <i@honeok.com>
#
# Thanks:
# https://github.com/xjasonlyu/maxmind-geoip
#
# SPDX-License-Identifier: Apache-2.0

ARG NGX_VERSION=""

FROM alpine:latest AS builder

LABEL maintainer="honeok <i@honeok.com>"

ARG NGX_VERSION=""
ARG GEOIP2_TAG=""

RUN set -ex \
    && apk add --update --no-cache --virtual .build-deps \
        binutils \
        build-base \
        curl \
        git \
        libmaxminddb-dev \
        pcre-dev \
        zlib-dev \
    && cd /tmp \
    && curl -Ls https://nginx.org/download/nginx-${NGX_VERSION}.tar.gz -o nginx-${NGX_VERSION}.tar.gz \
    && tar fxz nginx-${NGX_VERSION}.tar.gz \
    && git clone --depth=1 --branch ${GEOIP2_TAG} https://github.com/leev/ngx_http_geoip2_module.git \
    && cd nginx-${NGX_VERSION} \
    && ./configure --with-compat \
        --add-dynamic-module=../ngx_http_geoip2_module \
    && make modules \
    && strip objs/*.so \
    && apk del --no-network .build-deps \
    && rm -rf /var/cache/apk/*

FROM nginx:${NGX_VERSION}-alpine AS dist

LABEL maintainer="honeok <i@honeok.com>"

ARG NGX_VERSION=""

COPY --from=builder /tmp/nginx-${NGX_VERSION}/objs/*.so /usr/lib/nginx/modules/
COPY *.mmdb /usr/share/GeoIP/
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/conf.d/* /etc/nginx/conf.d/

RUN set -ex \
    && apk add --update --no-cache \
        libmaxminddb \
    && rm -f /etc/nginx/conf.d/default.conf \
    && curl -Lso /usr/share/nginx/html/favicon.ico https://m.360buyimg.com/i/jfs/t1/323476/2/22568/1018/68cf39ceF4ae3b432/6b7588e656baf098.webp \
    && rm -rf /var/cache/apk/*

HEALTHCHECK --timeout=10s --start-period=5s CMD curl -fs http://127.0.0.1:80/health || exit 1