# ipinfo Docker Image by honeok

[![Docker Pulls](https://img.shields.io/docker/pulls/honeok/ipinfo.svg?style=flat-square)](https://hub.docker.com/r/honeok/ipinfo)
[![Docker Image Size](https://img.shields.io/docker/image-size/honeok/ipinfo.svg?style=flat-square)](https://hub.docker.com/r/honeok/ipinfo)

[ipinfo][1] is a self-hosted, no-tracking, no-ads solution for displaying client IP information such as IP address, country, AS number/description.

Built based on the latest version of `Nginx`, retaining the latest features of `Nginx`!

## Prepare the host

If you need to install docker by yourself, follow the [official installation guide][2].

## Pull the image

```shell
docker pull honeok/ipinfo
```

This pulls the latest release of ipinfo.

It can be found at [Docker Hub][3].

## Start a container

```shell
docker run -d -p 80:80 --name ipinfo --restart unless-stopped honeok/ipinfo
```

If you want to put this container behind reverse proxy, set up an `X-Real-IP` header and pass the it to the container, so that it can use the header as the IP of the client.

Without any specified URI, the server will return IP address, country, AS, and user agent.

If you prefer to receive a machine-readable result, use path `/json` (without trailing slash), the result will look like:

```json
{
  "ip": "92.112.23.227",
  "country_code": "SG",
  "country_name": "Singapore",
  "asn": "209699",
  "as_desc": "Coaxial Cable LLC",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
}
```

You can also specify the following URI to retrieve certain info:

- `ip`: IP address
- `country`: Country code and name
- `country_code`: Country code
- `country_name`: Country name
- `as`: AS number and description
- `asn`: AS number
- `as_desc`: AS description
- `user_agent`: User agent string

**Warning**: The port number must be same as configuration and opened in firewall.

[1]: https://github.com/honeok/tools/blob/master/forge/ipinfo/README.md
[2]: https://docs.docker.com/install
[3]: https://hub.docker.com/r/honeok/ipinfo