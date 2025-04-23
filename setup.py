#!/usr/bin/env python3

import os, yaml, time, sys
from subprocess import Popen, PIPE
import hashlib
import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend

DEBUG = os.environ.get('DEBUG', "0")

# SSL cert stuff
CERT_444_PATH = os.environ.get('CERT_444_PATH', '/ssl/default444/cert.pem')
CERT_444_KEY_PATH = os.environ.get('CERT_444_KEY_PATH', '/ssl/default444/privkey.pem')
SETUP_REFRESH_FREQUENCY = os.environ.get('SETUP_REFRESH_FREQUENCY', None)

# multiple target conf
CONF_YML = os.environ.get('CONF_YML', None)

TEMPLATE_FILE_NGINX = os.environ.get('TEMPLATE_FILE_NGINX', '/etc/nginx/nginx.conf.tpl')
CONFIG_FILE_NGINX = os.environ.get('CONFIG_FILE_NGINX', '/etc/nginx/nginx.conf')
TEMPLATE_FILE_444 = os.environ.get('TEMPLATE_FILE_444', '/etc/nginx/conf.d/nginx_default444.conf.tpl')
TEMPLATE_FILE_HTTP = os.environ.get('TEMPLATE_FILE_HTTP', '/etc/nginx/conf.d/nginx_http.conf.tpl')
TEMPLATE_FILE_HTTPS = os.environ.get('TEMPLATE_FILE_HTTPS', '/etc/nginx/conf.d/nginx_https.conf.tpl')
CONF_OUT_DIR = os.environ.get('CONF_OUT_DIR', '/etc/nginx/conf.d/')

def run(cmd, splitlines=False, env=os.environ.copy()):
    # you had better escape cmd cause it's goin to the shell as is
    proc = Popen(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True, env=env)
    out, err = proc.communicate()
    if splitlines:
        out_split = []
        for line in out.split("\n"):
            line = line.strip()
            if line != '':
                out_split.append(line)
        out = out_split

    exitcode = int(proc.returncode)

    return (out, err, exitcode)

def log(s):
    print("SETUP: {}".format(s))

def debug(s):
    pass

if DEBUG[0].lower() in ("t", '1'):
    def debug(s):
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

    #vars["LIMIT_ZONE"] = hashlib.sha224(vars['PROXY_PASS_TARGET'].encode('utf-8')).hexdigest()
    ks = list(vars.keys())
    ks.sort(key=len, reverse=True)
    for k in ks:
        template = template.replace("${}".format(k), vars[k])

    debug(vars)

    return template

def certbot_certificates(lines):
    search = ["Certificate Name", "Domains", "Certificate Path", "Private Key Path"]
    key = search[0]

    certbot_certs = {}
    k = None
    for line in lines:
        line = line.strip()
        for s in search:
            if line.startswith("{}: ".format(s)):
                val = line.split("{}: ".format(s))[1].strip()
                if s == key:
                    k = val
                    certbot_certs[k] = {}
                else:
                    certbot_certs[k][s] = val

    return certbot_certs

def get_cert_path_for_domain(d, certbot_certs):
    debug("get_cert_path_for_domain {}".format(d))
    for k,v in certbot_certs.items():
        cert_domains = v["Domains"].split(" ")
        match = False
        for dom in cert_domains:
            if dom == d:
                match = True
            elif dom[0] == "*" and d.endswith(dom[1:]):
                match = True

            if match:
                return v["Certificate Path"], v["Private Key Path"]

    return None, None

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

        # by default return 444 to clients who do not specify a valid hostname
        if "default_444" in conf:
            log("setting up default 444")
            vars = os.environ.copy()

            vars["CERT_PATH"] = CERT_444_PATH
            vars["CERT_KEY_PATH"] = CERT_444_KEY_PATH

            applied_template = apply_template(TEMPLATE_FILE_444, vars)
            template_path = "{}/{}_http.conf".format(CONF_OUT_DIR, "default444")
            log("saving nginx config to {}".format(template_path))
            with open(template_path, "w") as fh:
                fh.write(applied_template)

        # grab list of certs from certbot
        (out, err, exitcode) = run("certbot certificates", splitlines=True)
        if exitcode != 0:
            raise Exception(err)
        certbot_certs = certbot_certificates(out)

        for k,v in conf["conf"].items():

            vars = os.environ.copy()
            log("handling {}".format(k))
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

            if "allow_only" in conf:
                v["ALLOW_ONLY"] = conf["allow_only"]

            if "LISTEN" in v:
                vars["LISTEN"] = v["LISTEN"]

            if "LISTEN_SSL" in v:
                vars["LISTEN_SSL"] = v["LISTEN_SSL"]

            if "ALLOW_ONLY" in v:
                for cidr in v["ALLOW_ONLY"]:
                    extra_options.append("allow {};".format(cidr))

                extra_options.append("deny all;")

            if "SKIP_PROXY_HEADERS" not in v:
                extra_options.append("proxy_set_header X-Real-IP $remote_addr;")
                extra_options.append("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
                extra_options.append("proxy_set_header Host $http_host;")

            if "EXTRA_OPTIONS" in v:
                for x in v["EXTRA_OPTIONS"]:
                    if x[-1] != ";":
                        x += ";"
                    extra_options.append(x)

            vars["EXTRA_OPTIONS"] = "\n".join(extra_options)

            applied_template = apply_template(TEMPLATE_FILE_HTTP, vars, basic_auth_file)

            template_path = "{}/{}_http.conf".format(CONF_OUT_DIR, k)
            log("saving nginx config to {}".format(template_path))
            with open(template_path, "w") as fh:
                fh.write(applied_template)

            debug(TEMPLATE_FILE_HTTP)
            debug(applied_template)

            cert_file, privkey = get_cert_path_for_domain(k, certbot_certs)

            # domain not in cert
            # or cert does not exist
            if cert_file == None:
                continue

            vars["CERT_PATH"] = cert_file
            vars["CERT_KEY_PATH"] = privkey
            websockets = (
                'proxy_redirect off;',
                'proxy_http_version 1.1;',
                'proxy_set_header Upgrade $http_upgrade;',
                'proxy_set_header Connection $connection_upgrade;'
            )
            vars["WEBSOCKETS"] = "\n".join(websockets)

            if "DISABLE_WEBSOCKETS" in v:
                vars["WEBSOCKETS"] = ""

            # vars["CERT_PATH"] = cert_path
            # vars["CERT_KEY_PATH"] = '/ssl/privkey.pem'

            applied_template = apply_template(TEMPLATE_FILE_HTTPS, vars, basic_auth_file)
            debug(TEMPLATE_FILE_HTTPS)
            debug(applied_template)

            template_path = "{}/{}_https.conf".format(CONF_OUT_DIR, k)
            log("saving nginx config to {}".format(template_path))
            with open(template_path, "w") as fh:
                fh.write(applied_template)

    else:
        # in this case there is no nginx, this container only handles cert generating

        run("setupssl")
        # regularly check if ssl cert needs to be renewed
        while True:
            time.sleep(86000)
            run("setupssl")
