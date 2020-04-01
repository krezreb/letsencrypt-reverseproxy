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

    server {

        listen 80 ;
        server_name _;
    
        limit_req zone=mylimit;

        client_body_buffer_size  10K;
        client_header_buffer_size 10k;
        client_max_body_size 10k;
        large_client_header_buffers 2 10k;
        
        client_body_timeout   5;
        client_header_timeout 5;
        keepalive_timeout     2 2;
        send_timeout          2;
        
        location /.well-known/acme-challenge {
        
            proxy_pass http://127.0.0.1:$ACME_CERT_PORT;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
        
        # send to https
    	return 301 https://$host$request_uri;
  
    }

    include /etc/nginx/conf.d/*.conf;

}