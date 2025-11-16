server {

    listen $LISTEN_SSL ssl $DEFAULT_SERVER;
    http2  on;

    server_name $SERVER_NAME;

    ssl_certificate         $CERT_PATH;
    ssl_certificate_key     $CERT_KEY_PATH;

    gzip             on;
    gzip_comp_level  2;
    gzip_min_length  1000;
    gzip_proxied     expired no-cache no-store private auth;
    gzip_types       text/plain application/x-javascript text/xml text/css application/xml;

    client_body_buffer_size  32K;
    client_header_buffer_size 10k;
    client_max_body_size 10k;

    location / {
        $AUTH_BASIC
        $AUTH_BASIC_USER_FILE
        client_max_body_size 0;
        $EXTRA_OPTIONS
        $PROXY_PASS
        $WEBSOCKETS
    }

}
