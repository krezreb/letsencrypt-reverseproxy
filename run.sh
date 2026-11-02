#!/usr/bin/env bash

trap "exit" INT TERM
trap "kill -9 0" EXIT

set -ue

setup

#chown -R nginx:nginx /ssl

echo "Starting nginx..."

# generate dummy self signed cert for 444 if needed
mkdir -p $(dirname $CERT_444_PATH) || true
openssl req -x509 -newkey rsa:4096 -keyout $CERT_444_KEY_PATH -out $CERT_444_PATH -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname" > /dev/null

# fire up nginx
nginx -g "daemon off;" &
NGINX_PID=$!

# wait for master to write pid file, else later `nginx -s reload` fails
while [ ! -s /var/run/nginx.pid ] ; do
    kill -0 $NGINX_PID 2>/dev/null || { echo "nginx failed to start" ; exit 1 ; }
    sleep 0.2
done

if [[ ${PROXY_PASS_TARGET:=""} != "" ]] ;  then

    if [[ $SETUP_REFRESH_FREQUENCY > 0 ]] ; then
        #echo ACME_CERT_PORT is $ACME_CERT_PORT
        setupssl && setup && nginx -s reload
        # regularly check if ssl cert needs to be renewed
        (while true ; do sleep $SETUP_REFRESH_FREQUENCY ; setupssl; setup; nginx -s reload ;  done) &
    else
        # set SETUP_REFRESH_FREQUENCY to zero if another container does the renewing
        (while true ; do sleep 86000 ; nginx -s reload ;  done) &
    fi
fi

wait