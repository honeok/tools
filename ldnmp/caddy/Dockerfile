# Description: This dockerfile is designed for containerizing the Caddy web server.
#
# Copyright (c) 2025 honeok <honeok@autistici.org>
#
# References:
# https://github.com/caddyserver/caddy-docker
# https://github.com/teddysun/across
# https://github.com/WJQSERVER-STUDIO/caddy
# https://github.com/kkkgo/caddy-docker
# https://cloud.tencent.com/developer/article/2345630
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG VERSION
FROM caddy:${VERSION}-builder AS builder
LABEL maintainer="honeok <honeok@autistici.org>"
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

ARG VERSION
FROM caddy:${VERSION}-alpine AS dist
LABEL maintainer="honeok <honeok@autistici.org>"
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
RUN set -ex \
    && apk upgrade \
    && apk add --no-cache tzdata \
    && rm -rf /var/cache/apk/*
ENV TZ=Asia/Shanghai