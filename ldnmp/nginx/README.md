# Nginx

[![GitHub Release](https://img.shields.io/github/v/tag/nginx/nginx.svg?style=flat-square&label=release&logo=github&color=blue)](https://github.com/nginx/nginx/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/honeok/nginx.svg?style=flat-square&logo=docker&color=blue&logoColor=white)](https://hub.docker.com/r/honeok/nginx)
[![Docker Image Size](https://img.shields.io/docker/image-size/honeok/nginx.svg?style=flat-square&logo=docker&color=blue&logoColor=white)](https://hub.docker.com/r/honeok/nginx)
[![Docker Image Version](https://img.shields.io/docker/v/honeok/nginx.svg?style=flat-square&logo=docker&color=blue&logoColor=white)](https://hub.docker.com/r/honeok/nginx)

[Nginx][1] is a high-performance HTTP and reverse proxy web server renowned for its stability, extensive feature set, straightforward configuration, and minimal resource usage.

This Docker image is designed for rapid deployment across various cloud computing platforms.

For additional details on Docker and containerization technologies, consult the [official document][2].

## Preparing the Host

If Docker is not yet installed, follow the [official installation guide][3] to set it up on your system.

## Purpose of This Build

This image was created to address specific requirements and explore creative enhancements.

<img src="https://m.360buyimg.com/i/jfs/t1/338939/26/15143/30360/68d64ae0Fb0b8e811/d71a4b0409db7ebd.webp" alt="Nginx" width="85%">

## Pull the image

```shell
docker pull honeok/nginx:alpine
```

## Start a container

Refer to the official [documentation][4] for guidance on running the container.

To leverage the unique features of this image, append the following lines to your configuration file:

```shell
vim /etc/nginx/nginx.conf

...
load_module modules/ngx_http_headers_more_filter_module.so;
load_module modules/ngx_http_zstd_filter_module.so;
load_module modules/ngx_http_zstd_static_module.so;
load_module modules/ngx_http_brotli_filter_module.so;
load_module modules/ngx_http_brotli_static_module.so;
load_module modules/ngx_http_acme_module.so;
...
```

**Note**: The port you configured must be opened in the firewall.

[1]: https://nginx.org
[2]: https://docs.docker.com
[3]: https://docs.docker.com/install
[4]: https://nginx.org/en/docs
