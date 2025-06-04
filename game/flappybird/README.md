## FlappyBird Docker Image by honeok

[![Docker Pulls](https://img.shields.io/docker/pulls/honeok/flappybird.svg?style=flat-square)](https://hub.docker.com/r/honeok/flappybird)
[![Docker Image Size](https://img.shields.io/docker/image-size/honeok/flappybird.svg?style=flat-square)](https://hub.docker.com/r/honeok/flappybird)

This is a fully self-contained FlappyBird game server with Docker image.

[FlappyBird][1] Docker image is a lightweight, browser-based FlappyBird game server that can be used for demonstrations, testing, or embedded use. It is built with JavaScript, CSS, and HTML.

Runs on any POSIX-compatible OS with minimal graphics or web support. It can be deployed locally, on servers, Raspberry Pi, or smart devices.

<img src="https://cdn.skyimg.net/up/2025/5/23/3ccc703c.webp" alt="FlappyBird" width="80%">

## Prepare the host

Docker images are built for quick deployment in various computing cloud providers.

For more information on docker and containerization technologies, refer to [official document][2].

If you need to install docker by yourself, follow the [official installation guide][3].

## Pull the image

```shell
docker pull honeok/flappybird
```

This image pulls the latest release of Flappybird.

It can be found at [Docker Hub][4].

## Start a container

```shell
docker run -d -p 80:80 --name flappybird --restart=unless-stopped honeok/flappybird
```

**Note**: The TCP port number `80` must be opened in firewall.

[1]: https://github.com/noanonoa/flappy-bird
[2]: https://docs.docker.com
[3]: https://docs.docker.com/install
[4]: https://hub.docker.com/r/honeok/flappybird