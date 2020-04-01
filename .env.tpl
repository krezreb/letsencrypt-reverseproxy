# FQDN of this nginx server
CERT_FQDN=

# email to us to generate the SSL certificate
CERT_EMAIL=

# target to proxy pass to
PROXY_PASS_TARGET=http|https://some_ip_or_hostname:port/path

# if you are reverse proxying to an https target, you might want to specify an ssl cert or CA cert to verify against
# See http://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_ssl_trusted_certificate
PROXY_SSL_TRUSTED_CERTIFICATE=/path/to/ca.pem

# if you specify PROXY_SSL_TRUSTED_CERTIFICATE above, set this to on, otherwise
# it serves no purpose 
PROXY_SSL_VERIFY=on 