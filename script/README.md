# script

<p align="center">
<img src="https://github.com/honeok/tools/actions/workflows/shellcheck.yml/badge.svg" alt="ShellCheck Status" />
</p>

## kernel.sh

Description: Based on xanmod and elrepo official source adaptation kernel upgrade one click script.

```shell
bash <(curl -sL https://gitlab.com/honeok/tools/raw/master/script/kernel.sh)
```
or
```shell
bash <(curl -sL https://github.com/honeok/tools/raw/master/script/kernel.sh)
```

## get-docker.sh

<p align="center">
<img src="https://hits.honeok.com/get-docker.svg?action=view&count_bg=%2379C83D&title_bg=%23555555&title=Hits&edge_flat=flase" alt="Total Runs"/>
</p>

Description: This script allows you to install the latest version of Docker on your server with a single command.

```shell
bash <(curl -sL https://gitlab.com/honeok/tools/raw/master/script/get-docker.sh)
```
or
```shell
bash <(curl -sL https://github.com/honeok/tools/raw/master/script/get-docker.sh)
```

## go.sh

Description: This script is used to install or update to the latest go version.

```shell
bash <(curl -sL https://github.com/honeok/tools/raw/master/script/go.sh)
```

## jq.sh

Description: This script is used to install the jq command through a binary file, which is more lightweight.

```shell
bash <(curl -sL https://github.com/honeok/tools/raw/master/script/jq.sh)
```

## iplocation.sh

Description: This script is used to query the ip ownership of mainland china from the general ip query interface.

Usage: `$1` is empty to query the server login user ip, and the parameter is the query parameter ip, which is only available in mainland `china`.

```shell
bash <(curl -sL https://github.com/honeok/tools/raw/master/script/iplocation.sh) 123.123.123.124
```

## dmesg.sh

Description: A simple script to view and analyze `dmesg` logs, quickly pinpointing system errors.

```shell
bash <(curl -sL https://gitlab.com/honeok/tools/raw/master/script/dmesg.sh)
```
or
```shell
bash <(curl -sL https://github.com/honeok/tools/raw/master/script/dmesg.sh)
```

## weather.sh

Description: A unique feature that displays the day's weather forecast to users based on their login IP address.

```shell
bash <(curl -sL https://gitlab.com/honeok/tools/raw/master/script/weather.sh)
```
or
```shell
bash <(curl -sL https://github.com/honeok/tools/raw/master/script/weather.sh)
```