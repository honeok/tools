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
    && cd /tmp \
    && wget https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_${TARGETOS}_${TARGETARCH}.tar.gz \
    && wget https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_sha256_checksums.txt \
    && grep -E "frp_${FRP_VERSION}_${TARGETOS}_${TARGETARCH}\.tar\.gz\$" frp_sha256_checksums.txt | sha256sum -c - \
    && tar fxz frp_${FRP_VERSION}_${TARGETOS}_${TARGETARCH}.tar.gz --strip 1 \
    && mkdir /etc/frp \
    && mv *.toml /etc/frp \
    && find . -maxdepth 1 -type f -regex './frp[cs]$' -exec mv {} /usr/bin/ \; \
    && rm -rf /var/cache/apk/* /tmp/*

CMD ["/usr/bin/frps", "-c", "/etc/frp/frps.toml"]
