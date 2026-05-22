# freenginx

[![GitHub Release](https://img.shields.io/github/v/tag/freenginx/nginx.svg?label=release&logo=github)](https://github.com/freenginx/nginx)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg?label=license&logo=github)](https://opensource.org/license/bsd-2-clause)

This image is built from [freenginx][1], an independent open-source fork of nginx.

[![freenginx](./assets/freenginx.png)](https://freenginx.org)

freenginx is an effort to preserve free and open development of nginx [engine x], an HTTP and reverse proxy server, a mail proxy server, and a generic TCP/UDP proxy server, originally written by Igor [Sysoev][2].

The freenginx sources and documentation are distributed under the [2-clause BSD-like license][3].

## Quick Start

```shell
docker run -d --name nginx -p 80:80 honeok/freenginx:alpine
```

See [Documentation][4].

## Acknowledgements

Special thanks to [Maxim Dounin][5] for his long-standing work on nginx and for creating and maintaining freenginx.

This container image is maintained independently by [honeok][6] and is not affiliated with, endorsed by, sponsored by, or supported by [F5, Inc][7] or the F5-maintained NGINX project.

NGINX is a registered trademark of [F5, Inc][7]. The names nginx and NGINX are used here only to describe software compatibility, historical origin, and upstream relationship.

[1]: https://freenginx.org
[2]: http://sysoev.ru/en
[3]: https://freenginx.org/LICENSE
[4]: https://freenginx.org/en/docs
[5]: https://mdounin.ru
[6]: https://www.honeok.com
[7]: https://www.f5.com
