limit_req_zone $binary_remote_addr zone=$LIMIT_ZONE:10m rate=5r/s;


server {

    listen 8080 ;
    server_name $SERVER_NAME;

    limit_req zone=$LIMIT_ZONE burst=20;

    client_body_buffer_size  10K;
    client_header_buffer_size 10k;
    client_max_body_size 10k;
    large_client_header_buffers 2 10k;
    
    client_body_timeout   5;
    client_header_timeout 5;
    keepalive_timeout     2 2;
    send_timeout          2;
    
    location ^~ /.well-known/acme-challenge {
    
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    location / {
        # send to https
        return 301 https://$host:$FRONT_HTTPS_PORT$request_uri;
    }
}
