# Nginx Docker Image by honeok

[![Docker Pulls](https://img.shields.io/docker/pulls/honeok/nginx.svg?style=flat-square)](https://hub.docker.com/r/honeok/nginx)
[![Docker Image Size](https://img.shields.io/docker/image-size/honeok/nginx.svg?style=flat-square)](https://hub.docker.com/r/honeok/nginx)
[![Docker Image Version](https://img.shields.io/docker/v/honeok/nginx.svg?style=flat-square)](https://hub.docker.com/r/honeok/nginx)

[Nginx][1] is a high-performance HTTP and reverse proxy web server renowned for its stability,

extensive feature set, straightforward configuration, and minimal resource usage.

This Docker image is designed for rapid deployment across various cloud computing platforms.

For additional details on Docker and containerization technologies, consult the [official document][2].

## Preparing the Host

If Docker is not yet installed, follow the [official installation guide][3] to set it up on your system.

## Purpose of This Build

This image was created to address specific requirements and explore creative enhancements.

<img src="https://img.honeok.com/file/1742913885322_5aca195c-6adf-4e4f-b84d-5455c5082f5b.png" alt="Nginx" width="80%">

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
load_module /etc/nginx/modules/ngx_http_zstd_filter_module.so;
load_module /etc/nginx/modules/ngx_http_zstd_static_module.so;
load_module /etc/nginx/modules/ngx_http_brotli_filter_module.so;
load_module /etc/nginx/modules/ngx_http_brotli_static_module.so;
load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;
...
```

[1]: https://nginx.org
[2]: https://docs.docker.com
[3]: https://docs.docker.com/install
[4]: https://nginx.org/en/docs