# Nginx Docker Image by honeok

[Nginx][1] is a high-performance HTTP and reverse proxy web server renowned for its stability,

extensive feature set, straightforward configuration, and minimal resource usage.

This Docker image is designed for rapid deployment across various cloud computing platforms.

For additional details on Docker and containerization technologies, consult the [official document][2].

## Preparing the Host

If Docker is not yet installed, follow the [official installation guide][3] to set it up on your system.

## Purpose of This Build

This image was created to address specific requirements and explore creative enhancements.

<img src="https://github.com/user-attachments/assets/7118b993-b78e-440e-a718-d8c38c78fd20" alt="Nginx" width="80%">

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
...
```

[1]: https://nginx.org
[2]: https://docs.docker.com
[3]: https://docs.docker.com/install
[4]: https://nginx.org/en/docs