# Description: This dockerfile is used to build the ipinfo container image.
#
# Copyright (c) 2025 honeok <honeok@duck.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM alpine:latest AS builder
LABEL maintainer="honeok <honeok@duck.com>"
ARG MAXMIND_KEY
ARG NGX_LVER
ARG GEOIP2_TAG
WORKDIR /GeoLite2
RUN set -ex \
    && apk add --no-cache --virtual .build-deps build-base git libmaxminddb-dev pcre-dev zlib-dev \
    && wget --tries=5 -qO GeoLite2-ASN.tar.gz "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_KEY}&edition_id=GeoLite2-ASN&suffix=tar.gz" \
    && wget --tries=5 -qO GeoLite2-ASN.tar.gz.sha256 "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_KEY}&edition_id=GeoLite2-ASN&suffix=tar.gz.sha256" \
    && sed -i 's/GeoLite2-ASN_[0-9]*.tar.gz/GeoLite2-ASN.tar.gz/g' GeoLite2-ASN.tar.gz.sha256 \
    && sha256sum -c GeoLite2-ASN.tar.gz.sha256 \
    && tar -zxf GeoLite2-ASN.tar.gz --strip 1 \
    && wget --tries=5 -qO GeoLite2-Country.tar.gz "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_KEY}&edition_id=GeoLite2-Country&suffix=tar.gz" \
    && wget --tries=5 -qO GeoLite2-Country.tar.gz.sha256 "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_KEY}&edition_id=GeoLite2-Country&suffix=tar.gz.sha256" \
    && sed -i 's/GeoLite2-Country_[0-9]*.tar.gz/GeoLite2-Country.tar.gz/g' GeoLite2-Country.tar.gz.sha256 \
    && sha256sum -c GeoLite2-Country.tar.gz.sha256 \
    && tar -zxf GeoLite2-Country.tar.gz --strip 1 \
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
LABEL maintainer="honeok <honeok@duck.com>"
ARG NGX_LVER
COPY --from=builder /tmp/nginx-${NGX_LVER}/objs/*.so /usr/lib/nginx/modules/
COPY --from=builder /GeoLite2/*.mmdb /usr/share/GeoIP/
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/conf.d/* /etc/nginx/conf.d/
RUN set -ex \
    && apk upgrade \
    && apk add --no-cache libmaxminddb \
    && rm -f /etc/nginx/conf.d/default.conf \
    && wget -qO /usr/share/nginx/html/favicon.ico "https://ipinfo.tw/favicon.ico" \
    && rm -rf /var/cache/apk/*
HEALTHCHECK --timeout=10s --start-period=5s CMD curl -fs http://127.0.0.1:80/health || exit 1