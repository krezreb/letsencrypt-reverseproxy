# letsencrypt-reverseproxy

Serves as a drop in nginx load balancer for handling SSL traffic and reverse proxying to a backend server.

# Requirements

- docker
- docker-compose
- a public IP and DNS entry pointing to it


# Usage

Let's say you have an app server on your private network: http://server.local.  You want to host this from another machine with a public ip and domain: appserver.example.com. letsencrypt-reverseproxy handles the SSL traffic on https://appserver.example.com and automatically renews the SSL certificate.

**docker-compose.yml:**

```
version : '3.0'

services:
    nginx:
        image: jbeeson/letsencrypt-reverseproxy
        ports:
            - "80:80"
            - "443:443"
        environment:
            - CERT_FQDN=appserver.example.com
            - CERT_EMAIL=email@example.com
            - PROXY_PASS_TARGET=http://server.local
        volumes:
            - ssl:/ssl

volumes:
    ssl:

```

To run it:

`docker-compose up -d`

All traffic to http://appserver.example.com is redirected to https

# TLS everywhere

Now let's take the above example and suppose that now you're backend server is running https with your own certificate authority.  The machine running letsencrypt-reverseproxy will need the backend server's CA certificate (a certificate file beings with `-----BEGIN CERTIFICATE-----`).  In this example, the CA certificate for the backend server is stored in `/ssl/backend-ca.cer` ..... not to be confused with Let's Encrypt's CA, stored in `/ssl/ca.cer`.


**docker-compose.yml:**


```
version : '3.0'

services:
    nginx:
        image: jbeeson/letsencrypt-reverseproxy
        ports:
            - "80:80"
            - "443:443"
        environment:
            - CERT_FQDN=appserver.example.com
            - CERT_EMAIL=email@example.com
            - PROXY_PASS_TARGET=https://server.local
            - PROXY_SSL_TRUSTED_CERTIFICATE=/ssl/ca-backend.cer
            # you must set PROXY_SSL_VERIFY=on, otherwise the above line has no effect
            - PROXY_SSL_VERIFY=on
        volumes:
            - ssl:/ssl

volumes:
    ssl:

```

# Additional information

Upon issue, LetsEncrypt SSL certificates are valid for 90 days.  `letsencrypt-reverseproxy` checks the validity of its certificate every 24 hours.  If the certificate expiry is in less than 31 days, `letsencrypt-reverseproxy` will attempt to renew it.  If renewal fails (for example, if the letsencrypt servers are inaccessible or if your server is offline),  `letsencrypt-reverseproxy` will try again in 24 hours.  So, whereas this architecture makes dependent on LetsEncrypt, their infrastructure would have to be inaccessible for an entire month for your certificate to publicly expire.

If you are new to making your own certificate authorities, here are a couple of handy links:
- https://www.simba.com/products/SEN/doc/Client-Server_user_guide/content/clientserver/configuringssl/signingca.htm
- https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/

