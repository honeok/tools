# Description: This dockerfile is used to timing build nezha dashboard v1 with an updated geoip database to fix flag display issues caused by changing ip segments.
#
# Copyright (c) 2025 honeok <i@honeok.com>
#
# References:
# https://github.com/nezhahq/nezha
#
# SPDX-License-Identifier: Apache-2.0

ARG NEZHA_VERSION=""

FROM golang:1.24-alpine AS builder
LABEL maintainer="honeok <i@honeok.com>"
ARG NEZHA_VERSION=""
WORKDIR /go/src/github.com/nezhahq/nezha
ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-D_LARGEFILE64_SOURCE=1"
RUN set -ex \
    && apk add --update --no-cache bash curl git gcc musl-dev yq-go \
    && git clone --depth=1 --branch ${NEZHA_VERSION} https://github.com/nezhahq/nezha.git .
COPY geoip.db /go/src/github.com/nezhahq/nezha/pkg/geoip/geoip.db
RUN set -ex \
    && chmod +x ./script/fetch-frontends.sh \
    && ./script/fetch-frontends.sh \
    && go install github.com/swaggo/swag/cmd/swag@latest \
    && swag init --pd -d . -g ./cmd/dashboard/main.go -o ./cmd/dashboard/docs --parseGoList=false \
    && go mod tidy -v \
    && go build -v -trimpath -ldflags="\
    -s -w -buildid= \
    -X 'github.com/nezhahq/nezha/service/singleton.Version=${NEZHA_VERSION#v}' \
    -extldflags '-static -fpic' \
    " -o /go/bin/dashboard ./cmd/dashboard

FROM ghcr.io/nezhahq/nezha:${NEZHA_VERSION} AS dist
LABEL maintainer="honeok <i@honeok.com>"
COPY --from=builder /go/bin/dashboard /dashboard/app