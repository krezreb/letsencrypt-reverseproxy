#!/usr/bin/env python3

import os, yaml, time, sys
from subprocess import Popen, PIPE
import hashlib
import argparse
from OpenSSL import crypto

DEBUG = os.environ.get('DEBUG', None)


# SSL cert stuff
ACME_CERT_PORT = int(os.environ.get('ACME_CERT_PORT', 8086))
CERT_EMAIL = os.environ.get('CERT_EMAIL', None)
CERT_FQDN = os.environ.get('CERT_FQDN', None)
CERT_PATH = os.environ.get('CERT_PATH', '/ssl/cert.pem')
CERT_EXPIRE_CUTOFF_DAYS = int(os.environ.get('CERT_EXPIRE_CUTOFF_DAYS', 31))
CERTFILE_UID = os.environ.get('CERTFILE_UID', None)
CERTFILE_GID = os.environ.get('CERTFILE_GID', None)
CHALLENGE_DNS_PROVIDER = os.environ.get('CHALLENGE_DNS_PROVIDER', None)

# proxy pass single target  vars
PROXY_PASS_TARGET = os.environ.get('PROXY_PASS_TARGET', None)
SETUP_REFRESH_FREQUENCY = os.environ.get('SETUP_REFRESH_FREQUENCY', None)
AUTH_BASIC_USER_FILE = os.environ.get('AUTH_BASIC_USER_FILE', None)

# multiple target conf
CONF_YML = os.environ.get('CONF_YML', None)

TEMPLATE_FILE_NGINX = os.environ.get('TEMPLATE_FILE_NGINX', '/etc/nginx/nginx.conf.tpl')
CONFIG_FILE_NGINX = os.environ.get('CONFIG_FILE_NGINX', '/etc/nginx/nginx.conf')
TEMPLATE_FILE_HTTP = os.environ.get('TEMPLATE_FILE_HTTP', '/etc/nginx/conf.d/nginx_http.conf.tpl')
TEMPLATE_FILE_HTTPS = os.environ.get('TEMPLATE_FILE_HTTPS', '/etc/nginx/conf.d/nginx_https.conf.tpl')
CONF_OUT_DIR = os.environ.get('CONF_OUT_DIR', '/etc/nginx/conf.d/')

def run(cmd, env=os.environ.copy()):
    # you had better escape cmd cause it's goin to the shell as is
    proc = Popen(cmd, stdout=sys.stdout, stderr=sys.stderr, shell=True, env=env)
    proc.communicate()

    exitcode = int(proc.returncode)

    return exitcode

def log(s):
    print("SETUP: {}".format(s))


def debug(s):
    if DEBUG != None:
        print("SETUP DEBUG: {}".format(s))

def apply_template( template_path, invars, basic_auth_file=None):

    # make a copy to prevent mods to vars in function from
    # spilling back up to caller
    vars = invars.copy()

    #open text file in read mode
    with open(template_path, "r") as fh:
        template = fh.read()

    if basic_auth_file != None:
        if "AUTH_BASIC" in vars:
            vars["AUTH_BASIC"] = "auth_basic \"{}\";".format(vars["AUTH_BASIC"])
        else:
            vars["AUTH_BASIC"] = "auth_basic \"HTTP Authentication Required\";"

        vars["AUTH_BASIC_USER_FILE"] = 'auth_basic_user_file "{}";'.format(basic_auth_file)
    else:
        vars["AUTH_BASIC"] = ""
        vars["AUTH_BASIC_USER_FILE"] = ""

    vars["LIMIT_ZONE"] = hashlib.sha224(vars['PROXY_PASS_TARGET'].encode('utf-8')).hexdigest()
    ks = list(vars.keys())
    ks.sort(key=len, reverse=True)
    for k in ks:
        template = template.replace("${}".format(k), vars[k])
    
    debug(vars)

    return template


if __name__ == '__main__':

    # parser = argparse.ArgumentParser()
    # parser.add_argument('--http-only', action='store_true', help='What port to use to issue certs')
    # parser.add_argument('--http-only', action='store_true', help='What port to use to issue certs')
    # args = parser.parse_args()
    
    if CONF_YML != None and os.path.exists(CONF_YML):
        log("reading {}".format(CONF_YML))
        with open(CONF_YML) as f:
            conf = yaml.load(f, Loader=yaml.FullLoader)

        vars = os.environ.copy()
        vars["ACCESS_LOG"]  = "access_log  /dev/stdout vhost;"
        vars["ERROR_LOG"]  = "error_log  /dev/stderr;"

        if "access_log" in conf:
            vars["ACCESS_LOG"] += "\naccess_log {} vhost;".format(conf["access_log"])
        if "error_log" in conf:
            vars["ERROR_LOG"] += "\nerror_log {};".format(conf["error_log"])

        applied_template = apply_template(TEMPLATE_FILE_NGINX, vars)

        with open(CONFIG_FILE_NGINX, "w") as fh:
            fh.write(applied_template)

        # fqdns = []

        # for k,v in conf["conf"].items():
        #     fqdns.append(k)

        cert_path = '/ssl/fullchain.cer'

        # no cert, yet
        subject_str = ""
        
        if os.path.isfile(cert_path):
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_path).read())
            subject = cert.get_subject()
            subject_str = "".join("/{:s}={:s}".format(name.decode(), value.decode()) for name, value in subject.get_components())



        for k,v in conf["conf"].items():

            vars = os.environ.copy()
            log("handing {}".format(k))
            if "PROXY_PASS_TARGET" not in v:
                log("no PROXY_PASS_TARGET provided for {}, skipping".format(k))
                continue

            vars["PROXY_PASS_TARGET"] = v["PROXY_PASS_TARGET"]
            
            vars["DEFAULT_SERVER"] =  ""

            if "IS_DEFAULT" in v:
                vars["DEFAULT_SERVER"] = "default_server"

            vars["SERVER_NAME"] = k

            basic_auth_file = None
            if "AUTH_BASIC_USER_FILE" in v:
                basic_auth_file = v["AUTH_BASIC_USER_FILE"]

            extra_options = []

            if "SKIP_PROXY_HEADERS" not in v:
                extra_options.append("proxy_set_header X-Real-IP $remote_addr;")
                extra_options.append("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
                extra_options.append("proxy_set_header Host $http_host;")

            for i,val in v.items():
                if i == i.lower():
                    extra_options.append('{} "{}";'.format(i, val))

            vars["EXTRA_OPTIONS"] = "\n".join(extra_options)

            applied_template = apply_template(TEMPLATE_FILE_HTTP, vars, basic_auth_file)

            template_path = "{}/{}_http.conf".format(CONF_OUT_DIR, k)
            log("saving nginx config to {}".format(template_path))
            with open(template_path, "w") as fh:
                fh.write(applied_template)

            debug(TEMPLATE_FILE_HTTP)
            debug(applied_template)

            # domain not in cert
            # or cert does not exist
            if k not in subject_str:
                continue

            # vars["CERT_PATH"] = cert_path
            # vars["CERT_KEY_PATH"] = '/ssl/privkey.pem'

            applied_template = apply_template(TEMPLATE_FILE_HTTPS, vars, basic_auth_file)
            debug(TEMPLATE_FILE_HTTPS)
            debug(applied_template)

            template_path = "{}/{}_https.conf".format(CONF_OUT_DIR, k)
            log("saving nginx config to {}".format(template_path))
            with open(template_path, "w") as fh:
                fh.write(applied_template)


    elif PROXY_PASS_TARGET == None:
        # in this case there is no nginx, this container only handles cert generating
        log("ACME_CERT_PORT is {}".format(ACME_CERT_PORT))

        run("setupssl")
        # regularly check if ssl cert needs to be renewed
        while True:
            time.sleep(86000)
            run("setupssl")

    else:
        log("PROXY_PASS_TARGET is {}".format(PROXY_PASS_TARGET))

        vars = os.environ.copy()
        vars["DEFAULT_SERVER"] =  "default_server"

        applied_template = apply_template(TEMPLATE_FILE_HTTP, vars, AUTH_BASIC_USER_FILE)

        with open("{}/reverse_proxy_http.conf".format(CONF_OUT_DIR), "w") as fh:
            fh.write(applied_template)


            cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())


            applied_template = apply_template(TEMPLATE_FILE_HTTPS, vars, AUTH_BASIC_USER_FILE)

            with open("{}/reverse_proxy_https.conf".format(CONF_OUT_DIR), "w") as fh:
                fh.write(applied_template)

