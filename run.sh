#!/usr/bin/env bash

trap "exit" INT TERM
trap "kill -9 0" EXIT

set -ue

echo SETUP_REFRESH_FREQUENCY is $SETUP_REFRESH_FREQUENCY

if [[ ${PROXY_PASS_TARGET:=""} == "" ]] ;  then
    # in this case there is no nginx, this container only handles cert generating
    echo ACME_CERT_PORT is $ACME_CERT_PORT
    setupssl --port 80
    # regularly check if ssl cert needs to be renewed
    while true ;
    do 
        sleep  86000
        setupssl --port $ACME_CERT_PORT
    done
    exit
fi

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

# build a list of all env var keys
envkeys=""
for l in $(printenv | cut -d"=" -f1); do 
    envkeys="$envkeys \\\$$l"
done

# support for basic auth
if [[ ${AUTH_BASIC_USER_FILE:=""} != "" ]] ;  then
    export AUTH_BASIC_USER_FILE="auth_basic_user_file \"$AUTH_BASIC_USER_FILE\";"
    if [[ ${AUTH_BASIC:=""} != "" ]] ;  then
        export AUTH_BASIC="auth_basic \"$AUTH_BASIC\";"
    else
        export AUTH_BASIC="auth_basic \"HTTP Authentication Required\";"
    fi
else
    export AUTH_BASIC=""
    export AUTH_BASIC_USER_FILE=""
fi

# apply env vars to template conf files
for f in $(find  /etc/nginx/ -type f | grep .tpl$ ); do

    filename=$(basename $f .tpl)
    envsubst "'$envkeys'" < $f > $(dirname $f)/$filename
done

echo "Starting nginx..."

# fire up nginx
nginx -g "daemon off;"