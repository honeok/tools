# Description: This dockerfile is used to build nezha dashboard v0 with the new geoip database to fix the correct national flag display.
#
# Copyright (c) 2025 honeok <i@honeok.com>
#
# References:
# https://github.com/naiba/nezha
#
# SPDX-License-Identifier: Apache-2.0

ARG NEZHA_VERSION=""

FROM golang:1.21-alpine AS builder
LABEL maintainer="honeok <i@honeok.com>"
ARG NEZHA_VERSION=""
WORKDIR /go/src/github.com/naiba/nezha
ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-D_LARGEFILE64_SOURCE=1"
RUN set -ex \
    && apk add --update --no-cache git gcc musl-dev \
    && git clone --depth=1 --branch ${NEZHA_VERSION} https://github.com/nezhahq/nezha.git .
COPY geoip.db /go/src/github.com/naiba/nezha/pkg/geoip/geoip.db
RUN set -ex \
    && go mod tidy -v \
    && go build -v -trimpath -ldflags="\
    -s -w -buildid= \
    -X 'github.com/naiba/nezha/service/singleton.Version=${NEZHA_VERSION#v}' \
    -extldflags '-static -fpic' \
    " -o /go/bin/dashboard ./cmd/dashboard

FROM ghcr.io/naiba/nezha-dashboard:${NEZHA_VERSION} AS dist
LABEL maintainer="honeok <i@honeok.com>"
COPY --from=builder /go/bin/dashboard /dashboard/app