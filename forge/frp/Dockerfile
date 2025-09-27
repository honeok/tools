# Description: This dockerfile is used build an all-in-one frps/frpc container for versatile deployments.
#
# Copyright (c) 2025 honeok <i@honeok.com>
# SPDX-License-Identifier: Apache-2.0

FROM alpine:latest AS dist

LABEL maintainer="honeok <i@honeok.com>"

ARG FRP_VERSION
ARG TARGETOS
ARG TARGETARCH

RUN set -ex \
    && apk upgrade \
    && apk add --update --no-cache tzdata \
    && wget -qO- https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_${TARGETOS}_${TARGETARCH}.tar.gz | tar xz -C /tmp --strip 1 \
    && mkdir -p /etc/frp \
    && mv /tmp/*.toml /etc/frp \
    && mv /tmp/frp* /usr/bin \
    && rm -rf /var/cache/apk/* /tmp/*

CMD ["/usr/bin/frps", "-c", "/etc/frp/frps.toml"]
