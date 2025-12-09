# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 honeok <i@honeok.com>

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
LABEL maintainer="honeok <i@honeok.com>"
WORKDIR /app
ARG TARGETOS
ARG TARGETARCH
COPY main.go .
ENV CGO_ENABLED=0
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
RUN set -ex \
    && apk add --update --no-cache tzdata \
    && go build -v -trimpath -ldflags="\
        -s -w -buildid= \
        -extldflags '-static -fpic' \
    " -o /go/bin/geolocation main.go

FROM --platform=$TARGETPLATFORM gcr.io/distroless/static
LABEL maintainer="honeok <i@honeok.com>"
ARG TZ=Asia/Shanghai
WORKDIR /app
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /go/bin/geolocation .
COPY index.html .
COPY favicon.ico .
ENV TZ=$TZ
EXPOSE 8080
ENTRYPOINT ["./geolocation"]
