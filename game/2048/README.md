## 2048 Docker Image by honeok

[![Docker Pulls](https://img.shields.io/docker/pulls/honeok/2048.svg?style=flat-square)](https://hub.docker.com/r/honeok/2048)
[![Docker Image Size](https://img.shields.io/docker/image-size/honeok/2048.svg?style=flat-square)](https://hub.docker.com/r/honeok/2048)


[2048][1] is a lightweight, The classic 2048 game, with its simple interface and addicting gameplay, challenges your digital merging strategy. The goal is to synthesize 2048 blocks.

Runs on any POSIX-compatible OS with minimal graphics or web support. It can be deployed locally, on servers, Raspberry Pi, or smart devices.

The Docker image will be built with the latest stable version of Nginx, aiming to leverage Nginx's newest security features.

<img src="https://cdn.skyimg.net/up/2025/6/4/c094d09b.webp" alt="2048" width="80%">

## Prepare the host

Docker images are built for quick deployment in various computing cloud providers.
For more information on docker and containerization technologies, refer to [official document][2].

If you need to install docker by yourself, follow the [official installation guide][3].

## Pull the image

```shell
docker pull honeok/2048
```

This image pulls the latest release of 2048.

It can be found at [Docker Hub][4].

## Start a container

```shell
docker run -d -p 80:80 --name 2048 --restart=unless-stopped honeok/2048
```

**Note**: The TCP port number `80` must be opened in firewall.

[1]: https://github.com/gabrielecirulli/2048
[2]: https://docs.docker.com
[3]: https://docs.docker.com/install
[4]: https://hub.docker.com/r/honeok/2048