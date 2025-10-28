# Description: This dockerfile creates an earthquake dashboard image, serving web application for real time USGS seismic data visualization.
#
# Copyright (c) 2025 honeok <i@honeok.com>
# SPDX-License-Identifier: Apache-2.0

FROM node:24.10-alpine AS deps
WORKDIR /app
COPY . .
RUN set -ex \
    && npm install \
    && npm run build

FROM python:3.14-alpine AS dist
ARG EARTHQUAKE_VERSION
ARG TZ=Asia/Shanghai
LABEL org.opencontainers.image.author="honeok <i@honeok.com>" \
    org.opencontainers.image.description="The earthquake dashboard container delivering real time visualization of global USGS seismic data." \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.source="https://github.com/honeok/tools" \
    org.opencontainers.image.title="earthquake" \
    org.opencontainers.image.version="$EARTHQUAKE_VERSION"
WORKDIR /app
COPY --from=deps /app/main.js static/main.js
COPY *.py .
COPY requirements.txt .
COPY templates/ templates/
COPY static/*.css static/
RUN set -ex \
    && python3 -m pip install --no-cache-dir -r requirements.txt --root-user-action=ignore \
    && rm -rf /var/cache/apk/* requirements.txt
EXPOSE 8000
ENV EARTHQUAKE_VERSION=$EARTHQUAKE_VERSION
ENV TZ=$TZ
ENTRYPOINT ["gunicorn", "-c", "gunicorn.conf.py", "main:app"]
