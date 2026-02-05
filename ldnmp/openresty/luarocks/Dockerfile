# syntax=docker/dockerfile:1
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2025 honeok <i@honeok.com>
#
# References:
# https://github.com/openresty/docker-openresty
# Acknowledgements:
# openresty and it's author agentzh <agentzh@gmail.com>
#                                   <admin@openresty.com>

FROM honeok/openresty:1.27.1.2-alpine@sha256:2c3d283d45a953aa7a6aa96c3ba4ff9e574e39a2f37a74e4d6d50719a0dd0295 AS dist

ARG RESTY_LUAROCKS_VERSION="3.12.2"

LABEL org.opencontainers.image.authors="Evan Wies <evan@neomantra.net>"
LABEL org.opencontainers.image.authors="honeok <i@honeok.com>"

RUN set -ex \
    && apk add --update --no-cache --virtual .build-deps \
        make \
        perl-dev \
    && cd /tmp \
    && curl -Ls https://luarocks.github.io/luarocks/releases/luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz -o luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && tar fxz luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && cd luarocks-${RESTY_LUAROCKS_VERSION} \
    && ./configure \
        --prefix=/usr/local/openresty/luajit \
        --with-lua=/usr/local/openresty/luajit \
        --with-lua-include=/usr/local/openresty/luajit/include/luajit-2.1 \
    && make build \
    && make install \
    && apk del --no-network .build-deps \
    && rm -rf /var/cache/apk/* /tmp/*

# Add LuaRocks paths
# If OpenResty changes, these may need updating:
#    /usr/local/openresty/bin/resty -e 'print(package.path)'
#    /usr/local/openresty/bin/resty -e 'print(package.cpath)'
ENV LUA_PATH="/usr/local/openresty/site/lualib/?.ljbc;/usr/local/openresty/site/lualib/?/init.ljbc;/usr/local/openresty/lualib/?.ljbc;/usr/local/openresty/lualib/?/init.ljbc;/usr/local/openresty/site/lualib/?.lua;/usr/local/openresty/site/lualib/?/init.lua;/usr/local/openresty/lualib/?.lua;/usr/local/openresty/lualib/?/init.lua;./?.lua;/usr/local/openresty/luajit/share/luajit-2.1/?.lua;/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua;/usr/local/openresty/luajit/share/lua/5.1/?.lua;/usr/local/openresty/luajit/share/lua/5.1/?/init.lua"
ENV LUA_CPATH="/usr/local/openresty/site/lualib/?.so;/usr/local/openresty/lualib/?.so;./?.so;/usr/local/lib/lua/5.1/?.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so;/usr/local/lib/lua/5.1/loadall.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so"
