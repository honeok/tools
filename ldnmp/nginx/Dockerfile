# Description: Install Brotli, Zstandard compression, and ModSecurity WAF for enhanced NGINX security and performance
#
# Copyright (C) 2024 -2025 kejilion <https://github.com/kejilion>
# Copyright (C) 2025 honeok <honeok@duck.com>
#
# License Information:
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License, version 3 or later.
#
# This program is distributed WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.

ARG NGX_IMAGE_BASE="nginx"
ARG NGX_IMAGE_TAG="alpine"

FROM alpine:latest AS builder

# Docker Build Arguments
ARG NGINX_VERSION ZSTD_VERSION

ARG NGX_J="4"

RUN set -ex \
    && apk update && apk upgrade \
    && apk add --no-cache --virtual .build-deps \
        automake \
        autoconf \
        brotli-dev \
        build-base \
        curl \
        curl-dev \
        geoip-dev \
        git \
        libtool \
        libxml2-dev \
        libxslt-dev \
        lmdb-dev \
        lua-dev \
        openssl-dev \
        pcre-dev \
        pkgconfig \
        yajl-dev \
        zlib-dev \
        linux-headers \
    && cd /tmp \
    && curl -L "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o nginx-${NGINX_VERSION}.tar.gz \
    && tar -zxf nginx-${NGINX_VERSION}.tar.gz \
    && git clone --recurse-submodules -j8 https://github.com/google/ngx_brotli \
    && git clone --depth 1 https://github.com/SpiderLabs/ModSecurity \
    && cd ModSecurity \
    && git submodule init \
    && git submodule update \
    && ./build.sh \
    && ./configure \
    && make \
    && make install \
    && cd /tmp \
    && git clone https://github.com/owasp-modsecurity/ModSecurity-nginx \
    && cd ModSecurity-nginx \
    && git checkout ef64996 \
    && cd /tmp \
    && curl -L "https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz" -o zstd-${ZSTD_VERSION}.tar.gz \
    && tar -xzf zstd-${ZSTD_VERSION}.tar.gz \
    && cd zstd-${ZSTD_VERSION} \
    && make clean \
    && CFLAGS="-fPIC" make -j${NGX_J} \
    && make -j${NGX_J} install \
    && cd /tmp \
    && git clone --depth=10 https://github.com/tokers/zstd-nginx-module.git \
    && cd nginx-${NGINX_VERSION} \
    && ./configure --with-compat \
        --add-dynamic-module=../ngx_brotli \
        --add-dynamic-module=../ModSecurity-nginx \
        --add-dynamic-module=../zstd-nginx-module \
    && make modules \
    && apk del .build-deps \
    && rm -rf /var/cache/apk/*

FROM ${NGX_IMAGE_BASE}:${NGX_IMAGE_TAG}

ARG CORERULESET_VERSION

COPY --from=builder /tmp/nginx-${NGINX_VERSION}/objs/*.so /etc/nginx/modules/
COPY --from=builder /usr/local/modsecurity/lib/* /usr/lib/

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
    && cd /tmp \
    && curl -L "https://github.com/coreruleset/coreruleset/archive/v${CORERULESET_VERSION}.tar.gz" -o v${CORERULESET_VERSION}.tar.gz \
    && tar -xzf v${CORERULESET_VERSION}.tar.gz --strip-components=1 -C /etc/nginx/modsec \
    && rm -f v${CORERULESET_VERSION}.tar.gz \
    && cd / \
    && curl -L -o /etc/nginx/modsec/plugins/wordpress-rule-exclusions-before.conf https://raw.githubusercontent.com/coreruleset/wordpress-rule-exclusions-plugin/master/plugins/wordpress-rule-exclusions-before.conf \
    && curl -L -o /etc/nginx/modsec/plugins/wordpress-rule-exclusions-config.conf https://raw.githubusercontent.com/coreruleset/wordpress-rule-exclusions-plugin/master/plugins/wordpress-rule-exclusions-config.conf \
    && curl -L -o /etc/nginx/modsec/plugins/ldnmp-before.conf https://raw.githubusercontent.com/kejilion/nginx/master/waf/ldnmp-before.conf \
    && cp /etc/nginx/modsec/crs-setup.conf.example /etc/nginx/modsec/crs-setup.conf \
    && echo 'SecAction "id:900110, phase:1, pass, setvar:tx.inbound_anomaly_score_threshold=30, setvar:tx.outbound_anomaly_score_threshold=16"' >> /etc/nginx/modsec/crs-setup.conf \
    && curl -L -o /etc/nginx/modsec/modsecurity.conf https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended \
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
    && curl -L -o /etc/nginx/modsec/unicode.mapping https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping \
    && rm -rf /var/cache/apk/* /tmp/*