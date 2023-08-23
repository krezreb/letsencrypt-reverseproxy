#!/usr/bin/env python3

import os, yaml, time, sys
from subprocess import Popen, PIPE

# SSL cert stuff
ACME_CERT_PORT = int(os.environ.get('ACME_CERT_PORT', 80))
CERT_EMAIL = os.environ.get('CERT_EMAIL', None)
CERT_FQDN = os.environ.get('CERT_FQDN', None)
CERT_PATH = os.environ.get('CERT_PATH', '/var/ssl/domain/cert.pem')
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

TEMPLATE_FILE = os.environ.get('TEMPLATE_FILE', '/etc/nginx/conf.d/reverse_proxy.conf.tpl')
CONF_OUT_DIR = os.environ.get('CONF_OUT_DIR', '/etc/nginx/conf.d/')

def run(cmd, env=os.environ.copy()):
    # you had better escape cmd cause it's goin to the shell as is
    proc = Popen(cmd, stdout=sys.stdout, stderr=sys.stderr, shell=True, env=env)
    proc.communicate()

    exitcode = int(proc.returncode)

    return exitcode

def log(s):
    print("SETUP: {}".format(s))

def apply_template( template_path, vars, basic_auth_file=None):

    #open text file in read mode
    with open(template_path, "r") as fh:
        template = fh.read()

    if basic_auth_file != None:
        vars["AUTH_BASIC"] = "auth_basic \"HTTP Authentication Required\";"
        vars["AUTH_BASIC_USER_FILE"] = 'auth_basic_user_file "{}";'.format(basic_auth_file)
    else:
        vars["AUTH_BASIC"] = ""
        vars["AUTH_BASIC_USER_FILE"] = ""


    ks = list(vars.keys())
    ks.sort(key=len, reverse=True)
    for k in ks:
        template = template.replace("${}".format(k), vars[k])
    
    return template


if __name__ == '__main__':

    if CONF_YML != None and os.path.exists(CONF_YML):
        log("reading {}".format(CONF_YML))
        with open(CONF_YML) as f:
            conf = yaml.load(f, Loader=yaml.FullLoader)

        for k,v in conf["conf"].items():
            vars = os.environ.copy()
            log("handing {}".format(k))
            if "PROXY_PASS_TARGET" not in v:
                log("no PROXY_PASS_TARGET provided for {}, skipping".format(k))
                continue

            cert_path = '/ssl/{}/cert.pem'.format(k)

            vars["CERT_PATH"] = cert_path
            vars["CERT_KEY_PATH"] = '/ssl/{}/privkey.pem'.format(k)

            vars["PROXY_PASS_TARGET"] = v["PROXY_PASS_TARGET"]
            vars["DEFAULT_SERVER"] =  ""

            if "IS_DEFAULT" in v:
                vars["DEFAULT_SERVER"] =  "default_server"

            vars["SERVER_NAME"] = k

            basic_auth_file = None
            if "AUTH_BASIC_USER_FILE" in v:
                basic_auth_file = v["AUTH_BASIC_USER_FILE"]

            applied_template = apply_template(TEMPLATE_FILE, vars, basic_auth_file)

            template_path = "{}/{}.conf".format(CONF_OUT_DIR, k)
            log("saving nginx config to {}".format(template_path))
            with open(template_path, "w") as fh:
                fh.write(applied_template)


    elif PROXY_PASS_TARGET == None:
        # in this case there is no nginx, this container only handles cert generating
        log("ACME_CERT_PORT is {}".format(ACME_CERT_PORT))

        run("setupssl --port 80")
        # regularly check if ssl cert needs to be renewed
        while True:
            time.sleep(86000)
            run("setupssl --port {}".format(ACME_CERT_PORT))

    else:
        log("PROXY_PASS_TARGET is {}".format(PROXY_PASS_TARGET))

        vars = os.environ.copy()
        vars["DEFAULT_SERVER"] =  "default_server"

        applied_template = apply_template(TEMPLATE_FILE, vars, AUTH_BASIC_USER_FILE)

        with open("{}/reverse_proxy.conf".format(CONF_OUT_DIR), "w") as fh:
            fh.write(applied_template)



