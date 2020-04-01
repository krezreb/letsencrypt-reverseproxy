server {
    
	listen 443 ssl http2 default_server;
	listen [::]:443 ssl http2 default_server;
	
	server_name _;

    ssl_certificate         $CERT_PATH;
    ssl_certificate_key     $CERT_KEY_PATH;

    gzip             on;
    gzip_comp_level  2;
    gzip_min_length  1000;
    gzip_proxied     expired no-cache no-store private auth;
    gzip_types       text/plain application/x-javascript text/xml text/css application/xml;

    location / {


        proxy_ssl_trusted_certificate $PROXY_SSL_TRUSTED_CERTIFICATE;
        proxy_ssl_verify $PROXY_SSL_VERIFY;

        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_pass $PROXY_PASS_TARGET;

        # For websockets
        proxy_redirect off;
        #proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}
