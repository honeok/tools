#!/usr/bin/env sh
# vim:sw=4:ts=4:et

set -e

entrypoint_log() {
    if [ -z "${RESTY_QUIET_LOGS:-}" ]; then
        echo "$@"
    fi
}

if [ "$1" = "nginx" ] || [ "$1" = "nginx-debug" ]; then
    if /usr/bin/find "/docker-entrypoint.d/" -mindepth 1 -maxdepth 1 -type f -print -quit 2>/dev/null; then
        entrypoint_log "$0: /docker-entrypoint.d/ is not empty, will attempt to perform configuration"

        entrypoint_log "$0: Looking for shell scripts in /docker-entrypoint.d/"
        /usr/bin/find "/docker-entrypoint.d/" -follow -type f -print | sort -V | while read -r SCRIPT; do
            case "$SCRIPT" in
                *.envsh )
                    if [ -x "$SCRIPT" ]; then
                        entrypoint_log "$0: Sourcing $SCRIPT";
                        # shellcheck source=/dev/null
                        . "$SCRIPT"
                    else
                        # warn on shell scripts without exec bit
                        entrypoint_log "$0: Ignoring $SCRIPT, not executable";
                    fi
                ;;
                *.sh )
                    if [ -x "$SCRIPT" ]; then
                        entrypoint_log "$0: Launching $SCRIPT";
                        "$SCRIPT"
                    else
                        # warn on shell scripts without exec bit
                        entrypoint_log "$0: Ignoring $SCRIPT, not executable";
                    fi
                ;;
                * )
                    entrypoint_log "$0: Ignoring $SCRIPT"
                ;;
            esac
        done

        entrypoint_log "$0: Configuration complete; ready for start up"
    else
        entrypoint_log "$0: No files found in /docker-entrypoint.d/, skipping configuration"
    fi
fi

exec "$@"