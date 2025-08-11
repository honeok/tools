# Description: This dockerfile is used to build a key management service server in a container.
#
# Copyright (c) 2025 honeok <i@honeok.com>
# Copyright (c) 2018-2024 Teddysun <i@teddysun.com>
#
# References:
# https://github.com/Wind4/vlmcsd
# https://github.com/teddysun/across
#
# Microsoft KMS Activation:
# https://wind4.github.io/vlmcsd
# https://learn.microsoft.com/zh-cn/windows-server/get-started/kms-client-activation-keys
#
# SPDX-License-Identifier: Apache-2.0

FROM alpine:latest AS builder
WORKDIR /vlmcsd
RUN set -ex \
    && apk add --update --no-cache build-base git make \
    && git clone --branch master --single-branch https://github.com/Wind4/vlmcsd.git . \
    && make

FROM alpine:latest AS dist
COPY --from=builder /vlmcsd/bin/vlmcsd /usr/bin/vlmcsd
RUN set -ex \
    && apk add --update --no-cache tzdata \
    && rm -rf /var/cache/apk/*
ENV TZ=Asia/Shanghai
EXPOSE 1688
ENTRYPOINT [ "vlmcsd" ]
CMD [ "-D", "-e" ]