user  $NGINX_USER;
worker_processes $WORKER_PROCESSES;

$TOPLEVEL_INCLUDES

error_log  /dev/stdout warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  $WORKER_CONNECTIONS;
    worker_aio_requests $WORKER_AIO_REQUESTS;
}

pcre_jit on;

http {
    include       /etc/nginx/mime.types;

    default_type  application/octet-stream;

    log_format vhost '$host - $remote_addr - $remote_user [$time_local] "$request" ' '$status $body_bytes_sent "$http_referer" ' '"$http_user_agent" $request_time';

    $ACCESS_LOG
    $ERROR_LOG

    charset utf-8;
    server_tokens off;

    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;

    server_names_hash_bucket_size 64;

    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;
    aio threads;
    aio_write on;
    directio 512k;
    keepalive_timeout  75 20;

    map $http_upgrade $connection_upgrade {
            default upgrade;
            '' close;
    }

    include /etc/nginx/conf.d/*.conf;

}
