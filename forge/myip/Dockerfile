# Description: containerized build of the myip program based on alpine.
#
# Copyright (c) 2025 honeok <honeok@duck.com>
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

FROM golang:1-alpine AS builder
WORKDIR /go/src
COPY . .
RUN set -ex \
    && CGO_ENABLED=0 GOOS=$TARGETOS \
    && go build -tags netgo -ldflags '-w -s' -o /go/bin/myip main.go

FROM alpine:latest
COPY --from=builder /go/bin/myip /usr/bin/myip
RUN set -ex \
    && apk update && apk upgrade \
    && apk add --no-cache \
        tzdata \
    && rm -rf /var/cache/apk/* /tmp/*
ENV TZ=Asia/Shanghai
EXPOSE 8080
ENTRYPOINT [ "myip" ]