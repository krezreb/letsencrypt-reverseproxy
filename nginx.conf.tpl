user  nginx;


error_log  /dev/stdout warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    
    default_type  application/octet-stream;    

    access_log  /dev/stdout   ;
    error_log  /dev/stderr    ;

    sendfile        on;

    charset utf-8;
    server_tokens off;
        
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    
    limit_req_zone $binary_remote_addr zone=mylimit:10m rate=5r/s;

    include /etc/nginx/conf.d/*.conf;

}