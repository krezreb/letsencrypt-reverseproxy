#!/usr/bin/env python3

import os, yaml, re
from subprocess import Popen, PIPE
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import datetime
from urllib.parse import urlparse
from urllib.request import urlopen
import socket
import argparse
from validate_email import validate_email
import tempfile
from pathlib import Path
import shutil

# SSL cert stuff
ACME_CERT_PORT = int(os.environ.get('ACME_CERT_PORT', 8086))
CERT_EMAIL = os.environ.get('CERT_EMAIL', None)
CERT_FQDN = os.environ.get('CERT_FQDN', None)
CERT_PATH = os.environ.get('CERT_PATH', '/ssl/cert.pem')
CERT_EXPIRE_CUTOFF_DAYS = int(os.environ.get('CERT_EXPIRE_CUTOFF_DAYS', 31))
CERTFILE_UID = os.environ.get('CERTFILE_UID', None)
ACME_CA_SERVER = os.environ.get('ACME_CA_SERVER', "zerossl")
CERTFILE_GID = os.environ.get('CERTFILE_GID', None)
CHALLENGE_DNS_PROVIDER = os.environ.get('CHALLENGE_DNS_PROVIDER', None)
DEBUG = os.environ.get('DEBUG', None)

# multiple target conf
CONF_YML = os.environ.get('CONF_YML', None)

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
    print("SETUPSSL: {}".format(s))

def debug(s):
    if DEBUG != None:
        print("SETUPSSL DEBUG: {}".format(s))

class SetupSSLException(Exception):
    pass



class SetupSSL(object):

    def __init__(self, fqdns=[], my_hostname=None, check_ip_url='https://ifconfig.io/ip'):
        self.my_ip = None
        self.fqdns = fqdns
        self.my_hostname = my_hostname
        self.check_ip_url = check_ip_url
        self.cert_sans = None
    
    @property
    # list of sans to provide cert
    # either hard coded in config["cert_sans"] if using wildcards
    # OR self.fqdns
    def get_cert_sans(self):
        if self.cert_sans != None:
            return self.cert_sans
        return self.fqdns

    # given a list of dns entries, some of which might contain wildcards
    # remove any dns entries that are encompassed in a wildcard
    # return entries
    # @property
    # def fqdns_wildcarded(self):
    #     fqdns = []
    #     wildcards = []

    #     for e in self.fqdns.copy():
    #         if "*" in e:
    #             wildcards.append(e)
    #         else:
    #             fqdns.append(e)

    #     if len(wildcards) == 0:
    #         # no wildcards
    #         return fqdns
        
    #     entries = []

    #     for f in fqdns:
    #         covered = False
    #         for wc in wildcards:
    #             r = wc.replace("*", "(.+)")
    #             if re.match(r, f):
    #                 # fqdn is covered by a wildcard
    #                 # don't append to entries
    #                 covered = True
    #         # not covered by a wildcard, append to entries
    #         if not covered:
    #             entries.append(f)

    #     reduced = wildcards + entries
    #     debug(reduced)
    #     return  reduced

    def points_to_me(self, s):
        self.get_my_ip()
        
        url = 'http://{}'.format(s)
        # from urlparse import urlparse  # Python 2
        parsed_uri = urlparse(url)
        domain = parsed_uri.netloc.split(':')[0]
        success = False
        ip = None
        try:
            ip = socket.gethostbyname(domain)
    
            if ip == self.my_ip:
                success = True
        except Exception as e:
            log(e)
            
        return (success, domain, ip, self.my_ip)

    def get_my_ip(self):
        
        if self.my_ip == None:
            self.my_ip = urlopen(self.check_ip_url).read().decode("utf-8").strip()
    
            if self.my_hostname != None:
                ip = socket.gethostbyname(self.my_hostname)
                if ip != self.my_ip:
                    raise SetupSSLException("ERROR RESOLVING MY IP: self.myhostname={} which resolves to ip {}. But according to {} my ip is {}".format(self.my_hostname, ip, self.check_ip_url, self.my_ip))
                    
            log("My ip appears to be {}".format(self.my_ip))
    
        return self.my_ip
    

    def check_cert(self):

        cert_exists = False
        cert_matches_conf = False
        expires_in_days = -1

        if not os.path.isfile(self.cert_file):
            return False, cert_matches_conf, 0

        log('cert_file {} found'.format(self.cert_file))
        cert_exists = True
        # cert already exists
        cert1 = crypto.load_certificate(crypto.FILETYPE_PEM, open(self.cert_file).read())
        exp = datetime.datetime.strptime(cert1.get_notAfter().decode("utf-8"), '%Y%m%d%H%M%SZ')
        
        expires_in = exp - datetime.datetime.utcnow()
    
        cert = x509.load_pem_x509_certificate(open(cert_path, 'rb').read(), default_backend())

        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        cert_sans = san.value.get_values_for_type(x509.DNSName)

        cert_matches_conf = True
        for d in self.cert_sans:
            if d not in cert_sans:
                cert_matches_conf = False
                break

        return cert_exists, cert_matches_conf, expires_in.days

    def get_le_cert(self):
        change = False
        fail = False
        
        log('get_le_cert()')
        
        cert_dir = "/ssl"

        acme_env = os.environ.copy()

        acme_env["HOME"] = "/etc/acme/"
        acme_env["DOMAIN_PATH"] = cert_dir
        acme_env["DOMAIN_CONF"] = "{}/domain.conf".format(cert_dir)
        acme_env["DOMAIN_SSL_CONF"] = "{}/domain.csr.conf".format(cert_dir)
        # acme_env["CSR_PATH"] = "{}/csr.csr".format(cert_dir)
        # acme_env["CERT_KEY_PATH"] = "{}/privkey.pem".format(cert_dir)
        # acme_env["CERT_PATH"] = "{}/cert.pem".format(cert_dir)

        cert_exists, cert_matches_conf, expires_in_days = self.check_cert()

        if cert_matches_conf:
            log('cert_file {} matches config'.format(self.cert_file))

            if expires_in_days <= 0:
                log("Found cert {} EXPIRED".format(", ".join(self.get_cert_sans)))
            else:
                log("Found cert {}, expires in {} days".format(", ".join(self.get_cert_sans), expires_in_days))
        
            if expires_in_days < self.expire_cutoff_days:
                log("Trying to renew cert {}".format(", ".join(self.get_cert_sans)))
                cmd = self.acme_renew_cmd()
                (out, err, exitcode) = run(cmd, env=acme_env)
                
                if exitcode == 0:
                    log("RENEW SUCCESS: Certificate {} successfully renewed".format(", ".join(self.get_cert_sans)))
                    change = True
        
                else:
                    log("RENEW FAIL: ERROR renewing certificate {}".format(", ".join(self.get_cert_sans)))
                    log(out)
                    log(err)
                    fail = True
            else:
                log("Nothing to do for cert file {}".format(self.cert_file))
        else :
            if not cert_exists:
                log('cert_file {} not found'.format(self.cert_file))
            else:
                log('cert_file {} does not match config'.format(self.cert_file))

            log('Requesting cert.... (this can take awhile)')

            if not os.path.isdir(cert_dir):
                os.makedirs(cert_dir)
                
            cmd = self.acme_issue_cmd()
            #debug("ACME_ENV")
            #debug(acme_env)
            temp_dir = tempfile.TemporaryDirectory()

            # issue cert in a temp dir
            # move to definitive dir if successful
            acme_env["CERT_PATH"] = temp_dir.name
            
            (out, err, exitcode) = run(cmd, env=acme_env)

            if exitcode != 0:
                log("Requesting cert for {}: FAILED".format(", ".join(self.get_cert_sans)))
                log(out)
                log(err)
                fail = True
    
            else:
                log("Requesting cert for {}: SUCCESS".format(", ".join(self.get_cert_sans)))
                change = True
                # move contents of temp dir to /ssl
                for src_file in temp_dir.name.glob('*.*'):
                    shutil.copy(src_file, "/ssl/")

            temp_dir.cleanup()


        return (change, fail)


    @property
    def acme_cli(self):
        cmd = "acme.sh "
        cmd += " --home /etc/acme --no-color"    
        cmd += " --force " # always force to avoid CA from bitching about not yet ripe certs    
        cmd += " --email {} ".format(self.cert_email)    
        cmd += " --server {} ".format(ACME_CA_SERVER)    
        return cmd
    
class SetupSSLHttp(SetupSSL):
    cert_email="you@example.com"
    acme_cert_http_port = 80

    def acme_renew_cmd(self):
        cmd = "{} --renew --standalone --httpport {} -d '{}'".format(self.acme_cli, self.acme_cert_http_port, "' -d '".join(self.get_cert_sans))
        debug(cmd)
        return cmd

    def acme_issue_cmd(self):
        cmd = "{} --issue --standalone --httpport {} -d '{}' ".format(self.acme_cli, self.acme_cert_http_port, "' -d '".join(self.get_cert_sans))
        debug(cmd)
        return cmd

class SetupSSLDns(SetupSSL):
    challenge_dns_provider=""

    def acme_renew_cmd(self):
        cmd = "{} --renew --dns {} -d '{}'".format(self.acme_cli, self.challenge_dns_provider, "' -d '".join(self.get_cert_sans))
        return cmd

    def acme_issue_cmd(self):
        cmd = "{} --issue --dns {} -d '{}'".format(self.acme_cli, self.challenge_dns_provider, "' -d '".join(self.get_cert_sans))
        return cmd


class SetupSSLRoute53(SetupSSL):
    challenge_dns_provider="dns_aws"

    def acme_renew_cmd(self):
        cmd = "{} --renew --dns {} -d '{}'".format(self.acme_cli, self.challenge_dns_provider, "' -d '".join(self.get_cert_sans))
        return cmd

    def acme_issue_cmd(self):
        cmd = "{} --issue --dns {} -d '{}' --ocsp-must-staple --keylength 4096 ".format(self.acme_cli, self.challenge_dns_provider, "' -d '".join(self.get_cert_sans))
        return cmd
    
parser = argparse.ArgumentParser()
parser.add_argument('--port', default=ACME_CERT_PORT, help='What port to use to issue certs')
parser.add_argument('--email', default=CERT_EMAIL, help='What email to use to issue certs')
parser.add_argument('--challenge-dns-provider', default=CHALLENGE_DNS_PROVIDER)
args = parser.parse_args()

def main(fqdns, cert_path, email, port, challenge_dns_provider=None, expire_cutoff_days=30, cert_sans=None):

    if challenge_dns_provider == "dns_aws":
        # use Route53 challenge
        s = SetupSSLRoute53(fqdns=fqdns)
        s.challenge_dns_provider = challenge_dns_provider
        log('Using DNS certificate generation with {}'.format(challenge_dns_provider))

    elif challenge_dns_provider != None:
        # use dns challenge
        s = SetupSSLDns(fqdns=fqdns)
        s.challenge_dns_provider = challenge_dns_provider
        log('Using DNS certificate generation with {}'.format(challenge_dns_provider))

    else:
        # use http challenge
        log('Using DNS certificate generation with http challenge')
        s = SetupSSLHttp(fqdns=fqdns)
        #s.acme_cert_http_port=port

    # email required in both cases
    s.cert_email=email
    s.cert_file = cert_path
    s.expire_cutoff_days=expire_cutoff_days
    s.fqdns = fqdns

    try:
        if not validate_email(email):
            raise Exception()
    except:
        raise SetupSSLException("CERT_EMAIL: The provided email for the certificate, {}, is not valid".format(email))

    if len(fqdns) == 0:
        raise SetupSSLException("ERROR: no certificate fqdn(s) set")

    log("")
    if cert_sans != None:
        s.cert_sans = cert_sans

    (change, fail) = s.get_le_cert()

    if CERTFILE_UID != None:
        run("chown -R {} {}".format(CERTFILE_UID, os.path.dirname(cert_path)))

    if CERTFILE_GID != None:
        run("chgrp -R {} {}".format(CERTFILE_GID, os.path.dirname(cert_path)))
    

if __name__ == '__main__':

    if CONF_YML != None and os.path.exists(CONF_YML):
        log("reading {}".format(CONF_YML))

        with open(CONF_YML) as f:
            conf = yaml.load(f, Loader=yaml.FullLoader)
        
        fqdns = []

        s = SetupSSL()

        for cert_fqdn,v in conf["conf"].items():
            log("handling {}".format(cert_fqdn))

            vars = os.environ.copy()
            if "PROXY_PASS_TARGET" not in v:
                log("no PROXY_PASS_TARGET provided for {}, skipping".format(cert_fqdn))
                continue

            (success, domain, ip, my_ip) = s.points_to_me(cert_fqdn)
            if not success:
                log("WARNING: {} does not point to this host.  FQDN resolves to {}, my ip is {}".format(fqdns, ip, my_ip))
                continue
    
            fqdns.append(cert_fqdn)

        if len(fqdns) == 0:
            log("WARNING: no domains configured to request certificates for")

        else:

            cert_sans = []
            if "cert_sans" in conf:
                cert_sans = conf["cert_sans"]

            cert_path = '/ssl/cert.pem'

            if not os.path.isdir(os.path.dirname(cert_path)):
                os.makedirs(os.path.dirname(cert_path))

            email = args.email

            challenge_dns_provider = args.challenge_dns_provider
            if "CHALLENGE_DNS_PROVIDER" in v:
                challenge_dns_provider = v["CHALLENGE_DNS_PROVIDER"]

            try:
                main(fqdns, cert_path, email, args.port, challenge_dns_provider, CERT_EXPIRE_CUTOFF_DAYS, cert_sans)
            except SetupSSLException:
                raise
            
    else:
        main(CERT_FQDN, CERT_PATH, args.email, args.port, args.challenge_dns_provider, CERT_EXPIRE_CUTOFF_DAYS)
  

        
