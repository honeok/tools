# Description: Self-compiled NGINX with a customized Server header.
#
# Copyright (C) 2025 honeok <honeok@duck.com>
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

FROM alpine:latest AS builder

RUN set -ex \
        && apk update && apk upgrade \
        && apk add --no-cache --virtual .build-deps \
            curl \
            gcc \
            libc-dev \
            linux-headers \
            make \
            openssl-dev \
            pcre2-dev \
            zlib-dev \
        && cd /tmp \
        && curl -fskL "https://nginx.org/download/nginx-1.27.4.tar.gz" -o nginx-1.27.4.tar.gz \
        && tar -zxf nginx-1.27.4.tar.gz \
        && cd nginx-1.27.4 \
        && sed -i 's/#define NGINX_VER\s*\"nginx\/\"/#define NGINX_VER \"honeok\/\"/' src/core/nginx.h \
        && sed -i 's/static u_char ngx_http_server_string\[\] = \"Server: nginx\"/static u_char ngx_http_server_string\[\] = \"Server: honeok\"/' src/http/ngx_http_header_filter_module.c \
        && ./configure \
            --prefix=/etc/nginx \
            --sbin-path=/usr/sbin/nginx \
            --modules-path=/usr/lib/nginx/modules \
            --conf-path=/etc/nginx/nginx.conf \
            --error-log-path=/var/log/nginx/error.log \
            --http-log-path=/var/log/nginx/access.log \
            --pid-path=/var/run/nginx.pid \
            --lock-path=/var/run/nginx.lock \
            --http-client-body-temp-path=/var/cache/nginx/client_temp \
            --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
            --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
            --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
            --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
            --with-perl_modules_path=/usr/lib/perl5/vendor_perl \
            --user=nginx \
            --group=nginx \
            --with-compat \
            --with-file-aio \
            --with-threads \
            --with-http_addition_module \
            --with-http_auth_request_module \
            --with-http_dav_module \
            --with-http_flv_module \
            --with-http_gunzip_module \
            --with-http_gzip_static_module \
            --with-http_mp4_module \
            --with-http_random_index_module \
            --with-http_realip_module \
            --with-http_secure_link_module \
            --with-http_slice_module \
            --with-http_ssl_module \
            --with-http_stub_status_module \
            --with-http_sub_module \
            --with-http_v2_module \
            --with-http_v3_module \
            --with-mail \
            --with-mail_ssl_module \
            --with-stream \
            --with-stream_realip_module \
            --with-stream_ssl_module \
            --with-stream_ssl_preread_module \
            --with-cc-opt='-Os -fstack-clash-protection -Wformat -Werror=format-security -fno-plt -g' \
            --with-ld-opt='-Wl,--as-needed,-O1,--sort-common -Wl,-z,pack-relative-relocs' \
        && make -j$(nproc) \
        && make install \
        && apk del .build-deps \
        && rm -rf /var/cache/apk/*

FROM nginx:alpine

COPY --from=builder /usr/sbin/nginx /usr/sbin/nginx