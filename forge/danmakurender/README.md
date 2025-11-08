# DanmakuRender

[![GitHub Release](https://img.shields.io/github/v/tag/SmallPeaches/DanmakuRender.svg?style=flat-square&label=release&logo=github&color=blue)](https://github.com/SmallPeaches/DanmakuRender/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/honeok/danmakurender.svg?style=flat-square&logo=docker&color=blue&logoColor=white)](https://hub.docker.com/r/honeok/danmakurender)
[![Docker Image Size](https://img.shields.io/docker/image-size/honeok/danmakurender.svg?style=flat-square&logo=docker&color=blue&logoColor=white)](https://hub.docker.com/r/honeok/danmakurender)
[![Docker Image Version](https://img.shields.io/docker/v/honeok/danmakurender.svg?style=flat-square&logo=docker&color=blue&logoColor=white)](https://hub.docker.com/r/honeok/danmakurender)

[DanmakuRender][1] is a lightweight tool for recording live streams with on-screen comments.

This Docker image is optimized for quick deployment across different cloud platforms.

For additional details on Docker and containerization technologies, refer to the [official documentation][2].

## Preparing the Host

If Docker isn’t installed yet, follow the [official installation guide][3] to install it on your system.

## Purpose of This Build

This image is designed for one-click deployment, removing the need for manual environment setup.

## Pull the image

```shell
docker pull honeok/danmakurender
```

## Start container

following content to the `docker-compose.yaml` file.

```shell
tee docker-compose.yaml >/dev/null <<'EOF'
services:
  danmakurender:
    image: honeok/danmakurender
    container_name: danmakurender
    restart: unless-stopped
    volumes:
      - $PWD/logs:/app/logs
      - $PWD/configs:/app/configs
    network_mode: bridge
EOF
```

Finally, run the following command to start the container.

```shell
docker compose up -d
```

For reference, see the DanmakuRender [Configuration Guide][4].

**Note**: Make sure the configured port is allowed through your firewall.

[1]: https://github.com/SmallPeaches/DanmakuRender
[2]: https://docs.docker.com
[3]: https://docs.docker.com/install
[4]: https://github.com/SmallPeaches/DanmakuRender/blob/v5/docs/usage.md
