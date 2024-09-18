certbot to the rescue!

- depending on the particular order in which certs were issues, they may be in a given directory or another.

e.g. imagine 2 wildcard domains
  *.jumidev.com
  *.jumidev.fr

If these are issued in a single command:

`certbot certonly --dns-route53 -n --agree-tos -m info@jumidev.com   --expand -d *.jumidev.fr -d *.jumidev.com`

They will end up in a single cert:

```
Found the following certs:
  Certificate Name: jumidev.fr
    Key Type: ECDSA
    Domains: *.jumidev.fr *.jumidev.com
    Expiry Date: 2024-12-17 11:37:14+00:00 (VALID: 89 days)
    Certificate Path: /etc/letsencrypt/live/jumidev.fr/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/jumidev.fr/privkey.pem
```

But if issued separately, 2 certs are generated

```
Found the following certs:
  Certificate Name: jumidev.com
    Key Type: ECDSA
    Domains: *.jumidev.com
    Expiry Date: 2024-12-17 11:59:15+00:00 (VALID: 89 days)
    Certificate Path: /etc/letsencrypt/live/jumidev.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/jumidev.com/privkey.pem
  Certificate Name: jumidev.fr
    Key Type: ECDSA
    Domains: *.jumidev.fr 
    Expiry Date: 2024-12-17 11:57:57+00:00 (VALID: 89 days)
    Certificate Path: /etc/letsencrypt/live/jumidev.fr/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/jumidev.fr/privkey.pem
```

So the python code needs to call `certbot certificates` to get a list of which cert is needed for a given domain