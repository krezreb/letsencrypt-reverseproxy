#!/usr/bin/env python3

import os, yaml
from subprocess import Popen, PIPE

from urllib.parse import urlparse
from urllib.request import urlopen
import socket
import argparse
from validate_email import validate_email

# SSL cert stuff
CERT_HTTP_CHALLENGE_PORT = os.environ.get('CERT_HTTP_CHALLENGE_PORT', None)
CERT_EMAIL = os.environ.get('CERT_EMAIL', None)
CERTFILE_UID = os.environ.get('CERTFILE_UID', None)
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
        self.certbot_certs = None
        self.fqdns = fqdns
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
    
    def run_certbot(self):

        log('run_certbot()')

        cmd = self.issue_cmd()
        log(cmd)
        (out, err, exitcode) = run(cmd)
        if exitcode == 0:
            log(out)
            return True

        log(err)
        return False

    @property
    def cert_cmd(self):
        cmd = "/usr/bin/certbot "
        cmd += " certonly --expand "    
        cmd += " -n --agree-tos  " # non interactive
        cmd += " -m {} ".format(self.cert_email)    
        return cmd
    

class SetupSSLDns(SetupSSL):
    challenge_dns_provider=""

    def issue_cmd(self):
        cmd = "{} --{} -d {}".format(self.cert_cmd, self.challenge_dns_provider, " -d ".join(self.fqdns))
        return cmd

parser = argparse.ArgumentParser()
parser.add_argument('--email', default=CERT_EMAIL, help='What email to use to issue certs')
parser.add_argument('--challenge-dns-provider', default=CHALLENGE_DNS_PROVIDER)
args = parser.parse_args()

def main(fqdns, email, challenge_dns_provider=None):

    if challenge_dns_provider != None:
        # use dns challenge
        s = SetupSSLDns(fqdns=fqdns)

        # https://eff-certbot.readthedocs.io/en/latest/using.html#third-party-plugins
        s.challenge_dns_provider = challenge_dns_provider
        log('Using DNS certificate generation with {}'.format(challenge_dns_provider))

    else:
        # todo reimplement http challenge
        pass

    # email required in both cases
    s.cert_email=email
    s.fqdns = fqdns

    try:
        if not validate_email(email):
            raise Exception()
    except:
        raise SetupSSLException("CERT_EMAIL: The provided email for the certificate, {}, is not valid".format(email))

    if len(fqdns) == 0:
        raise SetupSSLException("ERROR: no certificate fqdn(s) set")

    log("")
    success = s.run_certbot()    

if __name__ == '__main__':

    if CONF_YML != None and os.path.exists(CONF_YML):
        log("reading {}".format(CONF_YML))

        with open(CONF_YML) as f:
            conf = yaml.load(f, Loader=yaml.FullLoader)
        
        fqdns = []
        s = SetupSSL()

        for cert_fqdn,v in conf["conf"].items():
            log("handing {}".format(cert_fqdn))

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
            email = args.email
            challenge_dns_provider = args.challenge_dns_provider
            if "cert_sans" in conf:
                fqdns = conf["cert_sans"]

            try:
                main(fqdns, email, challenge_dns_provider)
            except SetupSSLException:
                raise
            
    else:
        raise Exception("No conf yml found")
  

        
