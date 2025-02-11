# Description: Build a PHP-FPM environment with essential extensions and optimized settings for smaller image size.
#
# Copyright (C) 2024 - 2025 honeok <honeok@duck.com>
# Copyright (C) 2024 - 2025 kejilion <lion12776@outlook.com>
#
# License Information:
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License, version 3 or later.
#
# This program is distributed WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.

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
        && curl -fsL https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions -o /usr/local/bin/install-php-extensions \
        && chmod +x /usr/local/bin/install-php-extensions \
        && /usr/local/bin/install-php-extensions \
            bcmath \
            exif \
            gd \
            Imagick/imagick@65e27f2bc0 \
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
        && echo "max_input_vars=3000" > /usr/local/etc/php/conf.d/max_input_vars.ini \
        && echo "max_input_vars=3000" > /usr/local/etc/php/conf.d/max_input_vars.ini \
        && curl -L -o /usr/local/etc/php/conf.d/optimized_php.ini https://raw.githubusercontent.com/kejilion/sh/master/optimized_php.ini \
        && curl -L -o /usr/local/etc/php-fpm.d/www.conf https://raw.githubusercontent.com/kejilion/sh/master/www-1.conf \
        && apk del .build-deps \
        && rm -f /usr/local/bin/install-php-extensions \
        && rm -rf /var/cache/apk/* /tmp/*