# Description: This dockerfile is used to build the ipinfo container image.
#
# Copyright (c) 2025 honeok <i@honeok.com>
#
# Thanks: https://github.com/xjasonlyu/maxmind-geoip
#
# SPDX-License-Identifier: Apache-2.0

# Second stage image name
ARG NGX_VERSION=""

FROM alpine:latest AS builder
LABEL maintainer="honeok <i@honeok.com>"
ARG NGX_VERSION=""
ARG GEOIP2_TAG=""
RUN set -ex \
    && apk add --update --no-cache --virtual .build-deps build-base git libmaxminddb-dev pcre-dev zlib-dev \
    && cd /tmp \
    && wget --tries=5 -qO nginx-${NGX_VERSION}.tar.gz https://nginx.org/download/nginx-${NGX_VERSION}.tar.gz \
    && tar -zxf nginx-${NGX_VERSION}.tar.gz \
    && git clone --depth=1 --branch ${GEOIP2_TAG} https://github.com/leev/ngx_http_geoip2_module.git \
    && cd nginx-${NGX_VERSION} \
    && ./configure --with-compat \
        --add-dynamic-module=../ngx_http_geoip2_module \
    && make modules \
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
    && apk add --update --no-cache libmaxminddb \
    && rm -f /etc/nginx/conf.d/default.conf \
    && wget --no-check-certificate -qO /usr/share/nginx/html/favicon.ico https://cdn.skyimg.net/up/2025/5/29/e8c32aa5.webp \
    && rm -rf /var/cache/apk/*
HEALTHCHECK --timeout=10s --start-period=5s CMD curl -fs http://127.0.0.1:80/health || exit 1