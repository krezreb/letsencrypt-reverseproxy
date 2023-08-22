#!/usr/bin/env bash

trap "exit" INT TERM
trap "kill -9 0" EXIT

set -ue

setup

if [[ ${PROXY_PASS_TARGET:=""} != "" ]] ;  then
    echo PROXY_PASS_TARGET is $PROXY_PASS_TARGET

    if [[ $SETUP_REFRESH_FREQUENCY > 0 ]] ; then
        echo ACME_CERT_PORT is $ACME_CERT_PORT
        setupssl --port 80
        # regularly check if ssl cert needs to be renewed
        (while true ; do sleep $SETUP_REFRESH_FREQUENCY ; setupssl --port $ACME_CERT_PORT; nginx -s reload ;  done) &
    else
        # set SETUP_REFRESH_FREQUENCY to zero if another container does the renewing
        (while true ; do sleep 86000 ; nginx -s reload ;  done) &
    fi
fi

echo "Starting nginx..."

# fire up nginx
nginx -g "daemon off;"