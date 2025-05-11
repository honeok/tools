# Description: build a lightweight php-fpm environment with essential extensions.
#
# Copyright (c) 2024-2025 honeok <honeok@duck.com>
#
# Thanks: kejilion <lion12776@outlook.com>
#
# Licensed under the Apache License, Version 2.0.
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES.
# See http://www.apache.org/licenses/LICENSE-2.0 for details.

FROM php:fpm-alpine

RUN set -ex \
        && apk update && apk upgrade \
        && apk add --no-cache --virtual .build-deps \
            autoconf \
            gcc \
            g++ \
            git \
            make \
            pkgconfig \
        && apk add --no-cache \
            imagemagick \
            imagemagick-dev \
            libgomp \
        && curl -fskL "https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions" -o /usr/local/bin/install-php-extensions \
        && chmod +x /usr/local/bin/install-php-extensions \
        && /usr/local/bin/install-php-extensions \
            bcmath \
            exif \
            gd \
            imagick \
            intl \
            mysqli \
            opcache \
            pdo_mysql \
            redis \
            zip \
        && echo "upload_max_filesize=50M" > /usr/local/etc/php/conf.d/uploads.ini \
        && echo "post_max_size=50M" > /usr/local/etc/php/conf.d/post.ini \
        && echo "memory_limit=256M" > /usr/local/etc/php/conf.d/memory.ini \
        && echo "max_execution_time=1200" > /usr/local/etc/php/conf.d/max_execution_time.ini \
        && echo "max_input_time=600" > /usr/local/etc/php/conf.d/max_input_time.ini \
        && echo "max_input_vars=3500" > /usr/local/etc/php/conf.d/max_input_vars.ini \
        && curl -fskL "https://github.com/kejilion/sh/raw/main/optimized_php.ini" -o /usr/local/etc/php/conf.d/optimized_php.ini \
        && curl -fskL "https://github.com/kejilion/sh/raw/main/www-1.conf" -o /usr/local/etc/php-fpm.d/www.conf \
        && apk del .build-deps \
        && rm -f /usr/local/bin/install-php-extensions \
        && rm -rf /var/cache/apk/* /tmp/*