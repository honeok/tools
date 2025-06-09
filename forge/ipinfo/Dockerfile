# Description: This dockerfile is used to build the ipinfo container image.
#
# Copyright (c) 2025 honeok <honeok@disroot.org>
#
# Thanks: https://github.com/xjasonlyu/maxmind-geoip
#
# SPDX-License-Identifier: Apache-2.0

FROM alpine:latest AS builder
LABEL maintainer="honeok <honeok@disroot.org>"
ARG NGX_LVER
ARG GEOIP2_TAG
RUN set -ex \
    && apk add --no-cache --virtual .build-deps build-base git libmaxminddb-dev pcre-dev zlib-dev \
    && cd /tmp \
    && wget --tries=5 -qO nginx-${NGX_LVER}.tar.gz "https://nginx.org/download/nginx-${NGX_LVER}.tar.gz" \
    && tar -zxf nginx-${NGX_LVER}.tar.gz \
    && git clone --depth=1 --branch ${GEOIP2_TAG} "https://github.com/leev/ngx_http_geoip2_module.git" \
    && cd nginx-${NGX_LVER} \
    && ./configure --with-compat \
        --add-dynamic-module=../ngx_http_geoip2_module \
    && make modules \
    && apk del .build-deps \
    && rm -rf /var/cache/apk/*

FROM nginx:stable-alpine AS dist
LABEL maintainer="honeok <honeok@disroot.org>"
ARG NGX_LVER
COPY --from=builder /tmp/nginx-${NGX_LVER}/objs/*.so /usr/lib/nginx/modules/
COPY *.mmdb /usr/share/GeoIP/
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/conf.d/* /etc/nginx/conf.d/
RUN set -ex \
    && apk upgrade \
    && apk add --no-cache libmaxminddb \
    && rm -f /etc/nginx/conf.d/default.conf \
    && wget --no-check-certificate -qO /usr/share/nginx/html/favicon.ico "https://cdn.skyimg.net/up/2025/5/29/e8c32aa5.webp" \
    && rm -rf /var/cache/apk/*
HEALTHCHECK --timeout=10s --start-period=5s CMD curl -fs http://127.0.0.1:80/health || exit 1