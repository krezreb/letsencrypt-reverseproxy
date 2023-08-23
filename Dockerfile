#FROM nginx:stable-alpine
FROM alpine:3

RUN mkdir -p /ssl

# acme.sh conf options
ENV AUTO_UPGRADE 0
ENV DOMAIN_PATH=/ssl
ENV DOMAIN_CONF=/ssl/domain.conf
ENV DOMAIN_SSL_CONF=/ssl/domain.csr.conf
ENV CSR_PATH=/ssl/csr.csr
ENV CERT_KEY_PATH=/ssl/privkey.pem
ENV CERT_PATH=/ssl/cert.pem

ENV LE_CONFIG_HOME=/etc/acme
ENV ACME_CERT_PORT=8086
ENV SETUP_REFRESH_FREQUENCY=86400
ENV FRONT_HTTPS_PORT=443

# reverse proxy config
ENV SERVER_NAME=_
ENV PROXY_PASS_TARGET=http://example.com/path
ENV PROXY_SSL_TRUSTED_CERTIFICATE=/ssl/cert.pem
ENV PROXY_SSL_VERIFY=off
ENV AUTH_BASIC=""
ENV AUTH_BASIC_USER_FILE=""
ENV CONF_YML="/config.yml"
ENV CONF_OUT_DIR=/etc/nginx/conf.d
ENV PYTHONUNBUFFERED=1

EXPOSE 80 443

RUN apk update -f \
  && apk --no-cache add -f \
  openssl gettext bash python3 py3-pip py-openssl \
  coreutils \
  bind-tools \
  git \ 
  build-deps build-base libffi-dev openssl-dev \
    nginx libnginx-mod-http-dav-ext nginx-mod-http-dav-ext  nginx-extras nginx \
  curl \
  socat \
  bash \
  tzdata \
  && rm -rf /var/cache/apk/* 

ADD requirements.txt / 

RUN pip3 install -r /requirements.txt

# install acme bash implementation
RUN mkdir -p /etc/acme \
    && cd /root \
    && git clone https://github.com/acmesh-official/acme.sh.git   \
    && cd ./acme.sh \
    && ./acme.sh --install \
    --home /usr/local/bin \
    --config-home /etc/acme \
    && cd .. && rm -rf acme.sh


ADD *.py /usr/local/bin/
RUN ln -s /usr/local/bin/setupssl.py  /usr/local/bin/setupssl
RUN ln -s /usr/local/bin/setup.py  /usr/local/bin/setup
ADD run.sh /run.sh
RUN chmod +x /usr/local/bin/setup*.py /run.sh

RUN rm -rf /etc/nginx/conf.d/* 

ADD nginx.conf /etc/nginx/
ADD reverse_proxy.conf.tpl /etc/nginx/conf.d/

CMD ["/run.sh"]