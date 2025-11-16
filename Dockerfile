FROM ubuntu:questing

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /ssl /docker-entrypoint.d

ENV SETUP_REFRESH_FREQUENCY=86400
ENV FRONT_HTTPS_PORT=443
ENV LISTEN=8080
ENV LISTEN_SSL=443
ENV WORKER_PROCESSES=auto
ENV WORKER_CONNECTIONS=2048
ENV WORKER_AIO_REQUESTS=512
ENV TOPLEVEL_INCLUDES=""
ENV NGINX_USER=ubuntu

# reverse proxy config
ENV CONF_YML="/config.yml"
ENV CONF_OUT_DIR=/etc/nginx/conf.d
ENV PYTHONUNBUFFERED=1

# default 444 page, if used
ENV CERT_444_PATH='/ssl/default444/cert.pem'
ENV CERT_444_KEY_PATH='/ssl/default444/privkey.pem'

EXPOSE 8080 443

RUN apt update -y \
    && apt install -y --no-install-recommends bash openssl certbot socat libnginx-mod-http-dav-ext nginx-extras nginx gettext python3 python3-pip tzdata \
    && rm -rf /var/cache/apt/*

# RUN apk update -f \
#     && apk --no-cache add -f \
#     openssl gettext bash python3 py3-pip \
#     coreutils \
#     bind-tools \
#     curl \
#     socat \
#     bash \
#     tzdata \
#     nginx-mod-http-dav-ext nginx-full nginx \
#     && rm -rf /var/cache/apk/*

ADD requirements.txt /

RUN pip3 install -r /requirements.txt --break-system-packages

ADD *.py /usr/local/bin/
RUN ln -s /usr/local/bin/setupssl.py  /usr/local/bin/setupssl
RUN ln -s /usr/local/bin/setup.py  /usr/local/bin/setup
ADD run.sh /run.sh
RUN chmod +x /usr/local/bin/setup*.py /run.sh

RUN rm -rf /etc/nginx/conf.d/*

ADD nginx.conf.tpl /etc/nginx/
ADD nginx_*.conf.tpl /etc/nginx/conf.d/

CMD ["/run.sh"]
