    server {

        listen 80 ;
        server_name $SERVER_NAME;
    
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
    	return 301 https://$host:$FRONT_HTTPS_PORT$request_uri;
  
    }


server {
    
	listen 443 ssl http2 default_server;
	listen [::]:443 ssl http2 default_server;
	
    ssl_certificate         $CERT_PATH;
    ssl_certificate_key     $CERT_KEY_PATH;

    gzip             on;
    gzip_comp_level  2;
    gzip_min_length  1000;
    gzip_proxied     expired no-cache no-store private auth;
    gzip_types       text/plain application/x-javascript text/xml text/css application/xml;

    server_name $SERVER_NAME;
    
    client_body_buffer_size  10K;
    client_header_buffer_size 10k;
    client_max_body_size 10k;
    large_client_header_buffers 2 10k;
    
    location / {
        $AUTH_BASIC
        $AUTH_BASIC_USER_FILE
    
        proxy_ssl_trusted_certificate $PROXY_SSL_TRUSTED_CERTIFICATE;
        proxy_ssl_verify $PROXY_SSL_VERIFY;
        client_max_body_size 0;

        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_pass $PROXY_PASS_TARGET;

        # For websockets
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "";

    }
}
