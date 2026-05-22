# Nginx

[![GitHub Release](https://img.shields.io/github/v/tag/nginx/nginx.svg?label=release&logo=github&color=blue)](https://github.com/nginx/nginx/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/honeok/nginx.svg?logo=docker&color=blue&logoColor=white)](https://hub.docker.com/r/honeok/nginx)
[![Docker Image Size](https://img.shields.io/docker/image-size/honeok/nginx.svg?logo=docker&color=blue&logoColor=white)](https://hub.docker.com/r/honeok/nginx)
[![Docker Image Version](https://img.shields.io/docker/v/honeok/nginx.svg?logo=docker&color=blue&logoColor=white)](https://hub.docker.com/r/honeok/nginx)

[Nginx][1] is a high-performance HTTP and reverse proxy web server renowned for its stability, extensive feature set, straightforward configuration, and minimal resource usage.

This Docker image is optimized for quick deployment across different cloud platforms.

For additional details on Docker and containerization technologies, refer to the [official documentation][2].

## Preparing the Host

If Docker isn’t installed yet, follow the [official installation guide][3] to install it on your system.

## Purpose of This Build

This image was created to address specific requirements and explore creative enhancements.

## Pull the image

```shell
docker pull honeok/nginx:alpine
```

## Start the Container

For detailed instructions on running the container, see the official [documentation][4].

To take advantage of this image’s unique features, add the following lines to your configuration file:

```shell
vim /etc/nginx/nginx.conf

load_module modules/ngx_http_acme_module.so;
load_module modules/ngx_http_brotli_filter_module.so;
load_module modules/ngx_http_brotli_static_module.so;
load_module modules/ngx_http_headers_more_filter_module.so;
load_module modules/ngx_http_zstd_filter_module.so;
load_module modules/ngx_http_zstd_static_module.so;
...
```

**Note**: Make sure the configured port is allowed through your firewall.

[1]: https://nginx.org
[2]: https://docs.docker.com
[3]: https://docs.docker.com/install
[4]: https://nginx.org/en/docs
