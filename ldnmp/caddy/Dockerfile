# Description: This dockerfile is used to add caddy common modules and recompile the container caddy web server.
#
# Copyright (c) 2025 honeok <i@honeok.com>
#
# References:
# https://github.com/caddyserver/caddy-docker
# https://github.com/teddysun/across
# https://github.com/WJQSERVER-STUDIO/caddy
# https://github.com/kkkgo/caddy-docker
# https://cloud.tencent.com/developer/article/2345630
#
# SPDX-License-Identifier: Apache-2.0

ARG CADDY_VERSION
FROM caddy:${CADDY_VERSION}-builder AS builder
LABEL maintainer="honeok <i@honeok.com>"
WORKDIR /usr/bin
RUN set -ex; \
    xcaddy build \
    --with github.com/caddyserver/cache-handler \
    --with github.com/ueffel/caddy-brotli \
    --with github.com/RussellLuo/caddy-ext/ratelimit \
    --with github.com/caddyserver/transform-encoder \
    --with github.com/caddyserver/replace-response \
    --with github.com/caddyserver/forwardproxy \
    --with github.com/caddyserver/ntlm-transport \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/caddy-dns/tencentcloud \
    --with github.com/caddy-dns/alidns \
    --with github.com/caddy-dns/acmedns

FROM caddy:${CADDY_VERSION}-alpine AS dist
LABEL maintainer="honeok <i@honeok.com>"
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
RUN set -ex \
    && apk add --update --no-cache tzdata \
    && rm -rf /var/cache/apk/*
ENV TZ=Asia/Shanghai