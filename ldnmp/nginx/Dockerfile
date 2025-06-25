# Description: This dockerfile is used to custom-compile nginx with brotli, zstandard compression, and modsecurity waf.
#
# Copyright (c) 2024-2025 honeok <honeok@disroot.org>
#
# Thanks: kejilion <lion12776@outlook.com>
#
# SPDX-License-Identifier: Apache-2.0

# Second stage image name
ARG NGX_LVER

FROM alpine:latest AS builder
LABEL maintainer="honeok <honeok@disroot.org>"
ARG NGX_LVER
ARG ZSTD_LVER

RUN set -ex \
    && apk update && apk upgrade \
    && apk add --no-cache --virtual .build-deps \
        autoconf \
        automake \
        brotli-dev \
        build-base \
        curl \
        curl-dev \
        geoip-dev \
        git \
        libxml2-dev \
        libxslt-dev \
        libtool \
        linux-headers \
        lmdb-dev \
        lua-dev \
        openssl-dev \
        pcre-dev \
        pcre2-dev \
        pkgconfig \
        yajl-dev \
        zlib-dev \
    && cd /tmp \
    && curl -Ls "https://nginx.org/download/nginx-${NGX_LVER}.tar.gz" -o nginx-${NGX_LVER}.tar.gz \
    && tar -zxf nginx-${NGX_LVER}.tar.gz \
    && git clone --recurse-submodules -j8 "https://github.com/google/ngx_brotli" \
    && git clone --depth 1 "https://github.com/owasp-modsecurity/ModSecurity" \
    && cd ModSecurity \
    && git submodule init \
    && git submodule update \
    && ./build.sh \
    && ./configure \
    && make && make install \
    && cd /tmp \
    && git clone "https://github.com/owasp-modsecurity/ModSecurity-nginx" \
    && curl -Ls "https://github.com/facebook/zstd/releases/download/v${ZSTD_LVER}/zstd-${ZSTD_LVER}.tar.gz" -o zstd-${ZSTD_LVER}.tar.gz \
    && tar -xzf zstd-${ZSTD_LVER}.tar.gz \
    && cd zstd-${ZSTD_LVER} \
    && make clean \
    && CFLAGS="-fPIC" make && make install \
    && cd /tmp \
    && git clone --depth=10 "https://github.com/tokers/zstd-nginx-module.git" \
    && cd nginx-${NGX_LVER} \
    && ./configure --with-compat \
        --add-dynamic-module=../ngx_brotli \
        --add-dynamic-module=../ModSecurity-nginx \
        --add-dynamic-module=../zstd-nginx-module \
    && make modules \
    && apk del .build-deps \
    && rm -rf /var/cache/apk/*

FROM nginx:${NGX_LVER}-alpine AS dist
LABEL maintainer="honeok <honeok@disroot.org>"
ARG NGX_LVER
ARG CORERULESET_LVER

COPY --from=builder /tmp/nginx-${NGX_LVER}/objs/*.so /etc/nginx/modules/
COPY --from=builder /usr/local/modsecurity/lib/* /usr/lib/
COPY html /usr/share/nginx/html

RUN set -ex \
    && apk update && apk upgrade \
    && apk add --no-cache \
        lua5.1 \
        lua5.1-dev \
        pcre \
        pcre-dev \
        yajl \
        yajl-dev \
    && mkdir -p /etc/nginx/modsec/plugins \
    && curl -Ls -O "https://github.com/coreruleset/coreruleset/archive/v${CORERULESET_LVER}.tar.gz" \
    && tar -xzf v${CORERULESET_LVER}.tar.gz --strip-components=1 -C /etc/nginx/modsec \
    && rm -f v${CORERULESET_LVER}.tar.gz \
    && curl -Ls "https://github.com/coreruleset/wordpress-rule-exclusions-plugin/raw/master/plugins/wordpress-rule-exclusions-before.conf" -o /etc/nginx/modsec/plugins/wordpress-rule-exclusions-before.conf \
    && curl -Ls "https://github.com/coreruleset/wordpress-rule-exclusions-plugin/raw/master/plugins/wordpress-rule-exclusions-config.conf" -o /etc/nginx/modsec/plugins/wordpress-rule-exclusions-config.conf \
    && curl -Ls "https://github.com/kejilion/nginx/raw/main/waf/ldnmp-before.conf" -o /etc/nginx/modsec/plugins/ldnmp-before.conf \
    && cp -f /etc/nginx/modsec/crs-setup.conf.example /etc/nginx/modsec/crs-setup.conf \
    && echo 'SecAction "id:900110, phase:1, pass, setvar:tx.inbound_anomaly_score_threshold=30, setvar:tx.outbound_anomaly_score_threshold=16"' >> /etc/nginx/modsec/crs-setup.conf \
    && curl -Ls "https://github.com/owasp-modsecurity/ModSecurity/raw/v3/master/modsecurity.conf-recommended" -o /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/SecPcreMatchLimit [0-9]\+/SecPcreMatchLimit 20000/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/SecPcreMatchLimitRecursion [0-9]\+/SecPcreMatchLimitRecursion 20000/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/^SecRequestBodyLimit\s\+[0-9]\+/SecRequestBodyLimit 52428800/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/^SecRequestBodyNoFilesLimit\s\+[0-9]\+/SecRequestBodyNoFilesLimit 524288/' /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/crs-setup.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/plugins/*-config.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/plugins/*-before.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/rules/*.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/plugins/*-after.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && ldconfig /usr/lib \
    && curl -Ls "https://github.com/owasp-modsecurity/ModSecurity/raw/v3/master/unicode.mapping" -o /etc/nginx/modsec/unicode.mapping \
    && curl -Ls "https://cdn.skyimg.net/up/2025/5/29/d655ae75.webp" -o /usr/share/nginx/html/favicon.ico \
    && rm -rf /var/cache/apk/*