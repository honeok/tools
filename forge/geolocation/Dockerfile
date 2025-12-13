# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 honeok <i@honeok.com>

FROM --platform=$BUILDPLATFORM alpine:latest AS deps
RUN set -ex \
    && apk add --update --no-cache tzdata

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
WORKDIR /app
ARG TARGETOS
ARG TARGETARCH
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
RUN set -ex \
    && go build -v -trimpath -ldflags="-s -w -buildid=" -o /go/bin/geolocation main.go

FROM --platform=$TARGETPLATFORM gcr.io/distroless/static:nonroot
LABEL maintainer="honeok <i@honeok.com>"
ARG TZ=Asia/Shanghai
WORKDIR /app
COPY --from=deps /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /go/bin/geolocation .
ENV TZ=$TZ
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["./geolocation"]
