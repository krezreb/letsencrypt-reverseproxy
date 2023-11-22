#!/usr/bin/env python3

import os, yaml
from subprocess import Popen, PIPE
from OpenSSL import crypto
import datetime
from urllib.parse import urlparse
from urllib.request import urlopen
import socket
import argparse
from validate_email import validate_email

# SSL cert stuff
ACME_CERT_PORT = int(os.environ.get('ACME_CERT_PORT', 80))
CERT_EMAIL = os.environ.get('CERT_EMAIL', None)
CERT_FQDN = os.environ.get('CERT_FQDN', None)
CERT_PATH = os.environ.get('CERT_PATH', '/ssl/cert.pem')
CERT_EXPIRE_CUTOFF_DAYS = int(os.environ.get('CERT_EXPIRE_CUTOFF_DAYS', 31))
CERTFILE_UID = os.environ.get('CERTFILE_UID', None)
ACME_CA_SERVER = os.environ.get('ACME_CA_SERVER', "zerossl")
CERTFILE_GID = os.environ.get('CERTFILE_GID', None)
CHALLENGE_DNS_PROVIDER = os.environ.get('CHALLENGE_DNS_PROVIDER', None)

# multiple target conf
CONF_YML = os.environ.get('CONF_YML', None)

def run(cmd, splitlines=False, env=os.environ.copy()):
    # you had better escape cmd cause it's goin to the shell as is
    proc = Popen([cmd], stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True, env=env)
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

class SetupSSLException(Exception):
    pass

class SetupSSL(object):

    def __init__(self, fqdn, my_hostname=None, check_ip_url='https://ifconfig.io/ip'):
        self.my_ip = None
        self.fqdn = fqdn
        self.my_hostname = my_hostname
        self.check_ip_url = check_ip_url
        
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
    


    def get_le_cert(self, cert_file, expire_cutoff_days=31 ):
        change = False
        fail = False
        
        log('get_le_cert()')
        
        cert_dir = os.path.dirname(cert_file)

        acme_env = os.environ.copy()

        acme_env["DOMAIN_PATH"] = cert_dir
        acme_env["DOMAIN_CONF"] = "{}/domain.conf".format(cert_dir)
        acme_env["DOMAIN_SSL_CONF"] = "{}/domain.csr.conf".format(cert_dir)
        acme_env["CSR_PATH"] = "{}/csr.csr".format(cert_dir)
        acme_env["CERT_KEY_PATH"] = "{}/privkey.pem".format(cert_dir)
        acme_env["CERT_PATH"] = "{}/cert.pem".format(cert_dir)

        if os.path.isfile(cert_file):
            log('cert_file {} found'.format(cert_file))
            
            # cert already exists
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())
            exp = datetime.datetime.strptime(cert.get_notAfter().decode("utf-8"), '%Y%m%d%H%M%SZ')
            
            expires_in = exp - datetime.datetime.utcnow()
            
            if expires_in.days <= 0:
                log("Found cert {} EXPIRED".format(self.fqdn))
            else:
                log("Found cert {}, expires in {} days".format(self.fqdn, expires_in.days))
        
            if expires_in.days < expire_cutoff_days:
                log("Trying to renew cert {}".format(self.fqdn))
                cmd = self.acme_renew_cmd()
                (out, err, exitcode) = run(cmd, env=acme_env)
                
                if exitcode == 0:
                    log("RENEW SUCCESS: Certificate {} successfully renewed".format(self.fqdn))
                    change = True
        
                else:
                    log("RENEW FAIL: ERROR renewing certificate {}".format(self.fqdn))
                    log(out)
                    log(err)
                    fail = True
            else:
                log("Nothing to do for cert file {}".format(cert_file))
        else :
            log('cert_file {} not found'.format(cert_file))

            if not os.path.isdir(cert_dir):
                os.makedirs(cert_dir)
                
            cmd = self.acme_issue_cmd()
            (out, err, exitcode) = run(cmd, env=acme_env)
            
            if exitcode != 0:
                log("Requesting cert for {}: FAILED".format(self.fqdn))
                log(cmd)
                log(err)
                fail = True
    
            else:
                log("Requesting cert for {}: SUCCESS".format(self.fqdn))
                change = True
        
        return (change, fail)


    @property
    def acme_cli(self):
        cmd = "acme.sh "
        cmd += " --server {} ".format(ACME_CA_SERVER)    
        cmd += " --email {} ".format(CERT_EMAIL)    
        return cmd
    
class SetupSSLHttp(SetupSSL):
    cert_email="you@example.com"
    acme_cert_http_port=80

    def acme_renew_cmd(self):
        cmd = "{} --renew --standalone --httpport {} -d {}".format(self.acme_cli, self.acme_cert_http_port, self.fqdn)
        return cmd

    def acme_issue_cmd(self):
        cmd = "{} --issue --standalone --httpport {} -d {} --email {} ".format(self.acme_cli, self.acme_cert_http_port, self.fqdn, self.cert_email)
        return cmd

class SetupSSLDns(SetupSSL):
    challenge_dns_provider=""

    def acme_renew_cmd(self):
        cmd = "{} --renew --dns {} -d {}".format(self.acme_cli, self.challenge_dns_provider, self.fqdn)
        return cmd

    def acme_issue_cmd(self):
        cmd = "{} --issue --dns {} -d {} --email {}".format(self.acme_cli, self.challenge_dns_provider, self.fqdn, self.cert_email)
        return cmd

parser = argparse.ArgumentParser()
parser.add_argument('--port', default=ACME_CERT_PORT, help='What port to use to issue certs')
parser.add_argument('--email', default=CERT_EMAIL, help='What email to use to issue certs')
parser.add_argument('--challenge-dns-provider', default=CHALLENGE_DNS_PROVIDER)

args = parser.parse_args()

def main(fqdn, cert_path, email, port, challenge_dns_provider=None, expire_cutoff_days=30):

    if challenge_dns_provider != None:
        # use dns challenge
        s = SetupSSLDns(fqdn=fqdn)
        s.challenge_dns_provider = challenge_dns_provider
        log('Using DNS certificate generation with {}'.format(challenge_dns_provider))

    else:
        # use http challenge
        log('Using DNS certificate generation with http challenge')
        s = SetupSSLHttp(fqdn=fqdn)
        s.acme_cert_http_port=port

    # email required in both cases
    s.cert_email=email

    try:
        if not validate_email(email):
            raise Exception()
    except:
        raise SetupSSLException("CERT_EMAIL: The provided email for the certificate, {}, is not valid".format(email))

    if fqdn == None:
        raise SetupSSLException("ERROR: no certificate fqdn set")

    (success, domain, ip, my_ip) = s.points_to_me(fqdn)
    if not success:
        raise SetupSSLException("certificate fqdn, ({}) does not point to me.  FQDN resolves to {}, my ip is {}".format(fqdn, ip, my_ip))
    log("")
    (change, fail) = s.get_le_cert(cert_path, expire_cutoff_days=expire_cutoff_days)

    if CERTFILE_UID != None:
        run("chown -R {} {}".format(CERTFILE_UID, os.path.dirname(cert_path)))

    if CERTFILE_GID != None:
        run("chgrp -R {} {}".format(CERTFILE_GID, os.path.dirname(cert_path)))
    

if __name__ == '__main__':

    if CONF_YML != None and os.path.exists(CONF_YML):
        log("reading {}".format(CONF_YML))

        with open(CONF_YML) as f:
            conf = yaml.load(f, Loader=yaml.FullLoader)

        for cert_fqdn,v in conf["conf"].items():
            log("handing {}".format(cert_fqdn))

            vars = os.environ.copy()
            if "PROXY_PASS_TARGET" not in v:
                log("no PROXY_PASS_TARGET provided for {}, skipping".format(cert_fqdn))
                continue

            cert_path = '/ssl/{}/cert.pem'.format(cert_fqdn)

            if not os.path.isdir(os.path.dirname(cert_path)):
                os.makedirs(os.path.dirname(cert_path))

            email = args.email
            if "CERT_EMAIL" in v:
                email = v["CERT_EMAIL"]

            challenge_dns_provider = args.challenge_dns_provider
            if "CHALLENGE_DNS_PROVIDER" in v:
                challenge_dns_provider = v["CHALLENGE_DNS_PROVIDER"]

            try:
                main(cert_fqdn, cert_path, email, args.port, challenge_dns_provider, CERT_EXPIRE_CUTOFF_DAYS)
            except SetupSSLException:
                continue
                
    else:
        main(CERT_FQDN, CERT_PATH, args.email, args.port, args.challenge_dns_provider, CERT_EXPIRE_CUTOFF_DAYS)
  

        
