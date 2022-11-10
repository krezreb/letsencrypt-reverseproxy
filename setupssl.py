#!/usr/bin/env python3

import os, json
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
CERT_PATH = os.environ.get('CERT_PATH', '/var/ssl/domain/cert.pem')
CERT_EXPIRE_CUTOFF_DAYS = int(os.environ.get('CERT_EXPIRE_CUTOFF_DAYS', 31))
CERTFILE_UID = os.environ.get('CERTFILE_UID', None)
CERTFILE_GID = os.environ.get('CERTFILE_GID', None)

def run(cmd, splitlines=False):
    # you had better escape cmd cause it's goin to the shell as is
    proc = Popen([cmd], stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
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
    
    def get_le_cert(self, cert_file, cert_email="you@example.com", expire_cutoff_days=31, acme_cert_http_port=80):
        change = False
        fail = False
        
        log('get_le_cert()')
        
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
                cmd = "acme.sh --renew --standalone --httpport {} -d {}".format(acme_cert_http_port, self.fqdn)
    
                (out, err, exitcode) = run(cmd)
                
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
            cmd = "acme.sh --issue --standalone --httpport {} -d {}".format(acme_cert_http_port, self.fqdn)
    
            cmd += ' --accountemail {} '.format(cert_email)
            (out, err, exitcode) = run(cmd)
            
            if exitcode != 0:
                log("Requesting cert for {}: FAILED".format(self.fqdn))
                log(cmd)
                log(err)
                fail = True
    
            else:
                log("Requesting cert for {}: SUCCESS".format(self.fqdn))
                change = True
        
        return (change, fail)

parser = argparse.ArgumentParser()
parser.add_argument('--port', default=ACME_CERT_PORT, help='What port to use to issue certs')
parser.add_argument('--email', default=CERT_EMAIL, help='What email to use to issue certs')
args = parser.parse_args()


if __name__ == '__main__':

    s = SetupSSL(fqdn=CERT_FQDN)

    try:
        if not validate_email(args.email):
            raise Exception()
    except:
        raise SetupSSLException("CERT_EMAIL: The provided email for the certificate, {}, is not valid".format(args.email))


    if CERT_FQDN != None:
        (success, domain, ip, my_ip) = s.points_to_me(CERT_FQDN)
        if not success:
            raise SetupSSLException("CERT_FQDN does not point to me.  CERT_FQDN={}, resolves to {}, my ip is {}".format(CERT_FQDN, ip, my_ip))
        log("")
        (change, fail) = s.get_le_cert(CERT_PATH, cert_email=args.email, expire_cutoff_days=CERT_EXPIRE_CUTOFF_DAYS, acme_cert_http_port=args.port)
        if CERTFILE_UID != None:
            run("chown -R {} {}".format(CERTFILE_UID, os.path.dirname(CERT_PATH)))

        if CERTFILE_GID != None:
            run("chgrp -R {} {}".format(CERTFILE_GID, os.path.dirname(CERT_PATH)))

    else:
        raise SetupSSLException("ERROR: CERT_FQDN environment variable not set")

     
                    

        
