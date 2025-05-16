# Description: Dockerfile for setting up a Key Management Service server.
#
# Copyright (c) 2025 honeok <honeok@duck.com>
# Copyright (c) 2018-2024 Teddysun <i@teddysun.com>
#
# References:
# https://github.com/Wind4/vlmcsd
# https://github.com/Wind4/vlmcsd-docker/blob/4195d04f687973a514e3fb663bd87161afd46697/Dockerfile
# https://github.com/teddysun/across/blob/master/docker/kms/Dockerfile
#
# Microsoft KMS Activation:
# https://wind4.github.io/vlmcsd
# https://learn.microsoft.com/zh-cn/windows-server/get-started/kms-client-activation-keys
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

FROM alpine:latest AS builder
WORKDIR /vlmcsd
RUN set -ex \
    && apk update && apk upgrade \
    && apk add --no-cache \
        build-base \
        git \
        make \
    && git clone --branch master --single-branch https://github.com/Wind4/vlmcsd.git . \
    && make

FROM alpine:latest
COPY --from=builder /vlmcsd/bin/vlmcsd /usr/bin/vlmcsd
RUN set -ex \
    && apk upgrade \
    && apk add --no-cache tzdata \
    && rm -rf /var/cache/apk/* /tmp/*
ENV TZ=Asia/Shanghai
EXPOSE 1688
ENTRYPOINT [ "vlmcsd" ]
CMD [ "-D", "-e" ]