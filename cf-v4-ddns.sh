#!/usr/bin/env bash
#
# Description: Automatically update your Cloudflare DNS record to the current IP.
#              Retrieves Cloudflare Domain ID and lists zones as a convenience.
#
# Modified By: Copyright (C) 2024 - 2025 honeok <honeok@duck.com>
#              Modifications made to improve efficiency, compatibility, and code style.
#
# Original Project: https://github.com/yulewang/cloudflare-api-v4-ddns
#
# License Information:
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License, version 3 or later.
#
# This program is distributed WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.

set \
    -o errexit \
    -o nounset \
    -o pipefail

# Place at:
# curl https://raw.githubusercontent.com/yulewang/cloudflare-api-v4-ddns/master/cf-v4-ddns.sh > /usr/local/bin/cf-ddns.sh && chmod +x /usr/local/bin/cf-ddns.sh
# run `crontab -e` and add next line:
# */1 * * * * /usr/local/bin/cf-ddns.sh >/dev/null 2>&1
# or you need log:
# */1 * * * * /usr/local/bin/cf-ddns.sh >> /var/log/cf-ddns.log 2>&1


# Usage:
# cf-ddns.sh -k cloudflare-api-key \
#            -u user@example.com \
#            -h host.example.com \     # fqdn of the record you want to update
#            -z example.com \          # will show you all zones if forgot, but you need this
#            -t A|AAAA                 # specify ipv4/ipv6, default: ipv4

# Optional flags:
#            -f false|true \           # force dns update, disregard local stored ip

# default config

# API key, see https://www.cloudflare.com/a/account/my-account,
# incorrect api-key results in E_UNAUTH error
CFKEY=

# Username, eg: user@example.com
CFUSER=

# Zone name, eg: example.com
CFZONE_NAME=

# Hostname to update, eg: homeserver.example.com
CFRECORD_NAME=

# Record type, A(IPv4)|AAAA(IPv6), default IPv4
CFRECORD_TYPE=A

# Cloudflare TTL for record, between 120 and 86400 seconds
CFTTL=120

# Ignore local file, update ip anyway
FORCE=false

WANIPSITE="http://ipv4.icanhazip.com"

# Site to retrieve WAN ip, other examples are: bot.whatismyipaddress.com, https://api.ipify.org/ ...
if [ "$CFRECORD_TYPE" = "A" ]; then
    :
elif [ "$CFRECORD_TYPE" = "AAAA" ]; then
    WANIPSITE="http://ipv6.icanhazip.com"
else
    echo "$CFRECORD_TYPE specified is invalid, CFRECORD_TYPE can only be A(for IPv4)|AAAA(for IPv6)"
    exit 2
fi

# get parameter
while getopts k:u:h:z:t:f: opts; do
    case ${opts} in
        k) CFKEY=${OPTARG} ;;
        u) CFUSER=${OPTARG} ;;
        h) CFRECORD_NAME=${OPTARG} ;;
        z) CFZONE_NAME=${OPTARG} ;;
        t) CFRECORD_TYPE=${OPTARG} ;;
        f) FORCE=${OPTARG} ;;
        *) 
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

# If required settings are missing just exit
if [ "$CFKEY" = "" ]; then
    echo "Missing api-key, get at: https://www.cloudflare.com/a/account/my-account"
    echo "and save in ${0} or using the -k flag"
    exit 2
fi
if [ "$CFUSER" = "" ]; then
    echo "Missing username, probably your email-address"
    echo "and save in ${0} or using the -u flag"
    exit 2
fi
if [ "$CFRECORD_NAME" = "" ]; then 
    echo "Missing hostname, what host do you want to update?"
    echo "save in ${0} or using the -h flag"
    exit 2
fi

# If the hostname is not a FQDN
if [ "$CFRECORD_NAME" != "$CFZONE_NAME" ] && [ -n "${CFRECORD_NAME##*"$CFZONE_NAME"}" ]; then
    CFRECORD_NAME="$CFRECORD_NAME.$CFZONE_NAME"
    echo " => Hostname is not a FQDN, assuming $CFRECORD_NAME"
fi

# Get current and old WAN ip
WAN_IP=$(curl -s ${WANIPSITE})
WAN_IP_FILE=$HOME/.cf-wan_ip_$CFRECORD_NAME.txt
if [ -f "$WAN_IP_FILE" ]; then
    OLD_WAN_IP=$(cat "$WAN_IP_FILE")
else
    echo "No file, need IP"
    OLD_WAN_IP=""
fi

# If WAN IP is unchanged an not -f flag, exit here
if [ "$WAN_IP" = "$OLD_WAN_IP" ] && [ "$FORCE" = false ]; then
    echo "WAN IP Unchanged, to update anyway use flag -f true"
    exit 0
fi

# Get zone_identifier & record_identifier
ID_FILE="$HOME/.cf-id_$CFRECORD_NAME.txt"
if [ -f "$ID_FILE" ] && [ "$(wc -l < "$ID_FILE")" -eq 4 ]; then
    read -r CFZONE_ID CFRECORD_ID FILE_CFZONE FILE_CFRECORD < "$ID_FILE"
    if [ "$FILE_CFZONE" == "$CFZONE_NAME" ] && [ "$FILE_CFRECORD" == "$CFRECORD_NAME" ]; then
        :
    else
        UPDATE_NEEDED=1
    fi
else
    UPDATE_NEEDED=1
fi

if [ "$UPDATE_NEEDED" ]; then
    echo "Updating zone_identifier & record_identifier"

    CFZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$CFZONE_NAME" \
        -H "X-Auth-Email: $CFUSER" -H "X-Auth-Key: $CFKEY" -H "Content-Type: application/json" \
        | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)

    CFRECORD_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records?name=$CFRECORD_NAME" \
        -H "X-Auth-Email: $CFUSER" -H "X-Auth-Key: $CFKEY" -H "Content-Type: application/json" \
        | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)

    {
        echo "$CFZONE_ID"
        echo "$CFRECORD_ID"
        echo "$CFZONE_NAME"
        echo "$CFRECORD_NAME"
    } > "$ID_FILE"
fi

# If WAN is changed, update cloudflare
echo "Updating DNS to $WAN_IP"

RESPONSE=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records/$CFRECORD_ID" \
    -H "X-Auth-Email: $CFUSER" \
    -H "X-Auth-Key: $CFKEY" \
    -H "Content-Type: application/json" \
    --data "{\"id\":\"$CFZONE_ID\",\"type\":\"$CFRECORD_TYPE\",\"name\":\"$CFRECORD_NAME\",\"content\":\"$WAN_IP\", \"ttl\":$CFTTL}")

if [ "$RESPONSE" != "${RESPONSE%success*}" ] && [ "$(echo "$RESPONSE" | grep "\"success\":true")" != "" ]; then
    echo "Updated succesfuly!"
    echo "$WAN_IP" > "$WAN_IP_FILE"
    exit
else
    echo 'Something went wrong :('
    echo "Response: $RESPONSE"
    exit 1
fi