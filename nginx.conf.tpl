user  nginx;
worker_processes auto;

error_log  /dev/stdout warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

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

    keepalive_timeout  75 20;

    include /etc/nginx/conf.d/*.conf;

}