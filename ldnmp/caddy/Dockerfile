# Description: This dockerfile is designed for containerizing the Caddy web server.
#
# Copyright (c) 2025 honeok <honeok@disroot.org>
#
# References:
# https://github.com/caddyserver/caddy-docker
# https://github.com/teddysun/across
# https://github.com/WJQSERVER-STUDIO/caddy
# https://github.com/kkkgo/caddy-docker
# https://cloud.tencent.com/developer/article/2345630
#
# SPDX-License-Identifier: Apache-2.0

ARG CADDY_LVER
FROM caddy:${CADDY_LVER}-builder AS builder
LABEL maintainer="honeok <honeok@disroot.org>"
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

ARG CADDY_LVER
FROM caddy:${CADDY_LVER}-alpine AS dist
LABEL maintainer="honeok <honeok@disroot.org>"
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
RUN set -ex \
    && apk upgrade \
    && apk add --no-cache tzdata \
    && rm -rf /var/cache/apk/*
ENV TZ=Asia/Shanghai