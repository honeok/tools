# SPDX-License-Identifier: Apache-2.0
#
# Description: This dockerfile is used to build a pre-configured, performance-tuned php-fpm image.
# Copyright (c) 2024-2025 honeok <i@honeok.com>

# References:
# https://github.com/kejilion/docker
# https://github.com/mlocati/docker-php-extension-installer

ARG PHP_VERSION=""

FROM php:${PHP_VERSION}-fpm-alpine AS dist

LABEL maintainer="honeok <i@honeok.com>"

RUN set -ex \
    && apk add --update --no-cache --virtual .build-deps \
        autoconf \
        gcc \
        g++ \
        git \
        imagemagick-dev \
        make \
        pkgconfig \
    && apk add --update --no-cache \
        imagemagick \
        libgomp \
    && curl -Ls https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions -o /usr/local/bin/install-php-extensions \
    && chmod +x /usr/local/bin/install-php-extensions \
    && /usr/local/bin/install-php-extensions \
        bcmath \
        exif \
        gd \
        intl \
        mysqli \
        opcache \
        pdo_mysql \
        redis \
        soap \
        zip \
    && echo "upload_max_filesize=50M" > /usr/local/etc/php/conf.d/uploads.ini \
    && echo "post_max_size=50M" > /usr/local/etc/php/conf.d/post.ini \
    && echo "memory_limit=256M" > /usr/local/etc/php/conf.d/memory.ini \
    && echo "max_execution_time=1200" > /usr/local/etc/php/conf.d/max_execution_time.ini \
    && echo "max_input_time=600" > /usr/local/etc/php/conf.d/max_input_time.ini \
    && echo "max_input_vars=3500" > /usr/local/etc/php/conf.d/max_input_vars.ini \
    && curl -Ls https://github.com/kejilion/sh/raw/main/optimized_php.ini -o /usr/local/etc/php/conf.d/optimized_php.ini \
    && curl -Ls https://github.com/kejilion/sh/raw/main/www-1.conf -o /usr/local/etc/php-fpm.d/www.conf \
    && apk del --no-network .build-deps \
    && rm -f /usr/local/bin/install-php-extensions \
    && rm -rf /var/cache/apk/*
