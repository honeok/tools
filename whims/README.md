# whims

## iplocation.sh

Description: This script is used to query the ip ownership of mainland china from the general ip query interface.

Usage: `$1` is empty to query the server login user ip, and the parameter is the query parameter ip, which is only available in mainland `china`.

```shell
bash <(curl -Ls https://gitlab.com/honeok/tools/raw/master/whims/iplocation.sh) 123.123.123.124
```

## weather.sh

Description: A unique feature that displays the day's weather forecast to users based on their login IP address.

```shell
bash <(curl -Ls https://github.com/honeok/tools/raw/master/whims/weather.sh)
```