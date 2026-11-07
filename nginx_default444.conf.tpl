limit_req_zone $binary_remote_addr zone=DEFAULT_444:10m rate=1r/s;

server {

    listen $LISTEN default_server;
    server_name "";

    limit_req zone=DEFAULT_444 burst=2;

    location / {
        return 444;
    }
}

server {

    limit_req zone=DEFAULT_444 burst=2;

    listen $LISTEN_SSL ssl default_server;

    server_name "";

    ssl_certificate         $CERT_PATH;
    ssl_certificate_key     $CERT_KEY_PATH;
   
    location / {
        return 444;

    }
}
