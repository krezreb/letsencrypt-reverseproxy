#!/usr/bin/env bash

trap "exit" INT TERM
trap "kill -9 0" EXIT

set -ue

echo ACME_CERT_PORT is $ACME_CERT_PORT
echo SETUP_REFRESH_FREQUENCY is $SETUP_REFRESH_FREQUENCY
echo PROXY_PASS_TARGET is $PROXY_PASS_TARGET

setupssl --port 80

# regularly check if ssl cert needs to be renewed
(while true ; do sleep $SETUP_REFRESH_FREQUENCY ; setupssl --port $ACME_CERT_PORT; nginx -s reload ;  done) &

# build a list of all env var keys
envkeys=""
for l in $(printenv | cut -d"=" -f1); do 
    envkeys="$envkeys \\\$$l"
done

# apply env vars to template conf files
for f in $(find  /etc/nginx/ -type f | grep .tpl$ ); do

    filename=$(basename $f .tpl)
    envsubst "'$envkeys'" < $f > $(dirname $f)/$filename
done

echo "Starting nginx..."

# fire up nginx
nginx -g "daemon off;"