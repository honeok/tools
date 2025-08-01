# Description: This dockerfile creates an openresty production image on alpine, integrating nginx with optimized configurations for high-performance web serving.
#
# Copyright (c) 2025 honeok <i@honeok.com>
#
# References:
# https://github.com/openresty/docker-openresty
# https://github.com/nginx/docker-nginx
# 
# Thanks: YichunZhang <agentzh@gmail.com>
#                     <admin@openresty.com>
#
# SPDX-License-Identifier: BSD-2-Clause

FROM alpine:latest AS builder

LABEL maintainer="honeok <i@honeok.com>"

# Docker Build Arguments
ARG RESTY_VERSION="1.27.1.2"
ARG ZSTD_VERSION=""

RUN set -ex \
    && apk add --update --no-cache --virtual .build-deps \
        build-base \
        curl \
        git \
        openssl-dev \
        pcre2-dev \
        perl \
        zlib-dev \
    && cd /tmp \
    && curl -Ls https://openresty.org/download/openresty-${RESTY_VERSION}.tar.gz -o openresty-${RESTY_VERSION}.tar.gz  \
    && tar fxz openresty-${RESTY_VERSION}.tar.gz \
    && curl -Ls https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz -o zstd-${ZSTD_VERSION}.tar.gz \
    && tar fxz zstd-${ZSTD_VERSION}.tar.gz \
    && cd zstd-${ZSTD_VERSION} \
    && make clean \
    && CFLAGS="-fPIC" make -j$(getconf _NPROCESSORS_ONLN) \
    && make install \
    && cd /tmp \
    && git clone --depth=10 https://github.com/tokers/zstd-nginx-module.git \
    && cd openresty-${RESTY_VERSION} \
    && ./configure \
        --with-compat \
        --add-dynamic-module=../zstd-nginx-module \
    && make \
    && apk del --no-network .build-deps \
    && rm -rf /var/cache/apk/*

FROM alpine:latest AS dist

LABEL maintainer="Evan Wies <evan@neomantra.net>"
LABEL maintainer="honeok <i@honeok.com>"

# Docker Build Arguments
ARG RESTY_VERSION="1.27.1.2"

# https://github.com/openresty/openresty-packaging/blob/master/alpine/openresty-openssl3/APKBUILD
ARG RESTY_OPENSSL_VERSION="3.4.1"
ARG RESTY_OPENSSL_PATCH_VERSION="3.4.1"
ARG RESTY_OPENSSL_URL_BASE="https://github.com/openssl/openssl/releases/download/openssl-${RESTY_OPENSSL_VERSION}"
# legacy: https://www.openssl.org/source/old/1.1.1
ARG RESTY_OPENSSL_BUILD_OPTIONS="enable-camellia enable-cms enable-fips enable-ktls enable-md2 enable-rc5 \
    enable-rfc3779 enable-seed enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers \
    "

# https://github.com/openresty/openresty-packaging/blob/master/alpine/openresty-pcre2/APKBUILD
ARG RESTY_PCRE_VERSION="10.44"
ARG RESTY_PCRE_SHA256="86b9cb0aa3bcb7994faa88018292bc704cdbb708e785f7c74352ff6ea7d3175b"
ARG RESTY_PCRE_BUILD_OPTIONS="--enable-jit --enable-pcre2grep-jit --disable-bsr-anycrlf --disable-coverage --disable-ebcdic --disable-fuzz-support \
    --disable-jit-sealloc --disable-never-backslash-C --enable-newline-is-lf --enable-pcre2-8 --enable-pcre2-16 --enable-pcre2-32 \
    --enable-pcre2grep-callout --enable-pcre2grep-callout-fork --disable-pcre2grep-libbz2 --disable-pcre2grep-libz --disable-pcre2test-libedit \
    --enable-percent-zt --disable-rebuild-chartables --enable-shared --disable-static --disable-silent-rules --enable-unicode --disable-valgrind \
    "

# https://github.com/openresty/openresty-packaging/blob/master/alpine/openresty/APKBUILD
ARG RESTY_CONFIG_OPTIONS="\
    --without-http_rds_json_module \
    --without-http_rds_csv_module \
    --with-http_iconv_module \
    --without-lua_rds_parser \
    --pid-path=/run/nginx.pid \
    --lock-path=/run/nginx.lock \
    --user=nginx \
    --group=nginx \
    --without-select_module \
    --without-poll_module \
    --with-threads \
    --with-file-aio \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_v3_module \
    --with-http_realip_module \
    --with-http_addition_module \
    --with-http_xslt_module=dynamic \
    --with-http_image_filter_module=dynamic \
    --with-http_geoip_module=dynamic \
    --with-http_sub_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_mp4_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_auth_request_module \
    --with-http_random_index_module \
    --with-http_secure_link_module \
    --with-http_degradation_module \
    --with-http_slice_module \
    --with-http_stub_status_module \
    --with-md5-asm \
    --with-sha1-asm \
    --http-client-body-temp-path=/var/cache/openresty/client_temp \
    --http-proxy-temp-path=/var/cache/openresty/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/openresty/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/openresty/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/openresty/scgi_temp \
    --with-mail \
    --with-mail_ssl_module \
    --without-mail_pop3_module \
    --without-mail_imap_module \
    --without-mail_smtp_module \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_realip_module \
    --with-stream_geoip_module \
    --with-stream_ssl_preread_module \
    --with-compat \
    --add-module=modules/ngx_brotli \
    "

ARG RESTY_CONFIG_OPTIONS_MORE=""
ARG RESTY_LUAJIT_OPTIONS="--with-luajit-xcflags='-DLUAJIT_NUMMODE=2 -DLUAJIT_ENABLE_LUA52COMPAT'"
ARG RESTY_PCRE_OPTIONS="--with-pcre-jit"

ARG RESTY_ADD_PACKAGE_BUILDDEPS=""
ARG RESTY_ADD_PACKAGE_RUNDEPS=""
ARG RESTY_EVAL_PRE_CONFIGURE=""
ARG RESTY_EVAL_POST_DOWNLOAD_PRE_CONFIGURE=""
ARG RESTY_EVAL_PRE_MAKE=""
ARG RESTY_EVAL_POST_MAKE=""

ARG RESTY_STRIP_BINARIES=""

# These are not intended to be user-specified
ARG RESTY_CONFIG_DEPS="--with-pcre \
    --with-cc-opt='-DNGX_LUA_ABORT_AT_PANIC -I/usr/local/openresty/pcre2/include -I/usr/local/openresty/openssl3/include' \
    --with-ld-opt='-L/usr/local/openresty/pcre2/lib -L/usr/local/openresty/openssl3/lib -Wl,-rpath,/usr/local/openresty/pcre2/lib:/usr/local/openresty/openssl3/lib' \
    "

COPY --from=builder /tmp/openresty-${RESTY_VERSION}/build/nginx-*/objs/*.so /usr/local/openresty/nginx/modules/

RUN set -ex \
# create nginx user/group first, to be consistent throughout docker variants
    && addgroup -g 101 -S nginx \
    && adduser -S -D -H -u 101 -h /var/cache/nginx -s /sbin/nologin -G nginx -g nginx nginx \
# let's build binaries from the published packaging sources
    && apk add --update --no-cache --virtual .build-deps \
        brotli-dev \
        build-base \
        binutils \
        coreutils \
        gd-dev \
        geoip-dev \
        git \
        libxslt-dev \
        linux-headers \
        make \
        perl-dev \
        readline-dev \
        zlib-dev \
        ${RESTY_ADD_PACKAGE_BUILDDEPS} \
    && apk add --no-cache \
        curl \
        gd \
        geoip \
        libgcc \
        libxslt \
        tzdata \
        zlib \
        ${RESTY_ADD_PACKAGE_RUNDEPS} \
    && cd /tmp \
    && curl -Ls "${RESTY_OPENSSL_URL_BASE}/openssl-${RESTY_OPENSSL_VERSION}.tar.gz" -o openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
    && tar fxz openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
    && cd openssl-${RESTY_OPENSSL_VERSION} \
# patching openssl 3.x for openresty
    && curl -Ls https://github.com/openresty/openresty/raw/master/patches/openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch | patch -p1 \
    && ./config \
        shared zlib -g \
        --prefix=/usr/local/openresty/openssl3 \
        --libdir=lib \
        -Wl,-rpath,/usr/local/openresty/openssl3/lib \
        ${RESTY_OPENSSL_BUILD_OPTIONS} \
    && make -j$(getconf _NPROCESSORS_ONLN) \
    && make -j$(getconf _NPROCESSORS_ONLN) install_sw \
    && cd /tmp \
    && curl -Ls https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${RESTY_PCRE_VERSION}/pcre2-${RESTY_PCRE_VERSION}.tar.gz -o pcre2-${RESTY_PCRE_VERSION}.tar.gz \
    && echo "${RESTY_PCRE_SHA256}  pcre2-${RESTY_PCRE_VERSION}.tar.gz" | shasum -a 256 --check \
    && tar fxz pcre2-${RESTY_PCRE_VERSION}.tar.gz \
    && cd pcre2-${RESTY_PCRE_VERSION} \
    && CFLAGS="-g -O3" ./configure \
        --prefix=/usr/local/openresty/pcre2 \
        --libdir=/usr/local/openresty/pcre2/lib \
        ${RESTY_PCRE_BUILD_OPTIONS} \
    && CFLAGS="-g -O3" make -j$(getconf _NPROCESSORS_ONLN) \
    && CFLAGS="-g -O3" make -j$(getconf _NPROCESSORS_ONLN) install \
    && cd /tmp \
    && curl -Ls https://openresty.org/download/openresty-${RESTY_VERSION}.tar.gz -o openresty-${RESTY_VERSION}.tar.gz \
    && tar fxz openresty-${RESTY_VERSION}.tar.gz \
    && cd openresty-${RESTY_VERSION} \
    && git clone --recurse-submodules -j8 https://github.com/google/ngx_brotli modules/ngx_brotli \
    && eval ./configure -j$(getconf _NPROCESSORS_ONLN) ${RESTY_CONFIG_DEPS} ${RESTY_CONFIG_OPTIONS} ${RESTY_CONFIG_OPTIONS_MORE} ${RESTY_LUAJIT_OPTIONS} ${RESTY_PCRE_OPTIONS} \
    && make -j$(getconf _NPROCESSORS_ONLN) \
    && make -j$(getconf _NPROCESSORS_ONLN) install \
    && if [ -n "${RESTY_STRIP_BINARIES}" ]; then \
        rm -Rf /usr/local/openresty/openssl3/bin/c_rehash /usr/local/openresty/openssl3/lib/*.a /usr/local/openresty/openssl3/include \
        && find /usr/local/openresty/openssl3 -type f -perm -u+x -exec strip --strip-unneeded '{}' \; \
        && rm -Rf /usr/local/openresty/pcre2/bin /usr/local/openresty/pcre2/share \
        && find /usr/local/openresty/pcre2 -type f -perm -u+x -exec strip --strip-unneeded '{}' \; \
        && rm -Rf /usr/local/openresty/luajit/lib/*.a /usr/local/openresty/luajit/share/man \
        && find /usr/local/openresty/luajit -type f -perm -u+x -exec strip --strip-unneeded '{}' \; \
        && find /usr/local/openresty/nginx -type f -perm -u+x -exec strip --strip-unneeded '{}' \; ; \
    fi \
    && rm -f /usr/local/openresty/nginx/conf/*.default \
    && rm -rf /tmp/* \
    && apk del --no-network .build-deps \
# Temporary file cache directory.
    && mkdir -p /var/cache/openresty \
    && curl -Ls https://openresty.org/favicon.ico -o /usr/local/openresty/nginx/html/favicon.ico \
# Add `envsubst` for templating environment variables.
    && apk add --no-cache gettext-envsubst \
# if we have leftovers from building, let's purge them (including extra, unnecessary build deps)
    && rm -rf /var/cache/apk/* \
# forward request and error logs to docker log collector.
    && ln -sf /dev/stdout /usr/local/openresty/nginx/logs/access.log \
    && ln -sf /dev/stderr /usr/local/openresty/nginx/logs/error.log \
# create a docker-entrypoint.d directory
    && mkdir /docker-entrypoint.d

ENV TZ=UTC
# Add additional binaries into PATH for convenience.
ENV PATH=$PATH:/usr/local/openresty/luajit/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/bin

# Copy nginx configuration files.
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY nginx.vh.default.conf /etc/nginx/conf.d/default.conf
COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

EXPOSE 80

# Use SIGQUIT instead of default SIGTERM to cleanly drain requests.
# See https://github.com/openresty/docker-openresty/blob/master/README.md#tips--pitfalls
# See https://github.com/nginx/docker-nginx/issues/377
STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]