#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import sys, os
sys.path.append(os.getcwd())
import setup

class TestSanity(unittest.TestCase):

    def setUp(self):
        mockfile = os.path.dirname(__file__)+"/mock_certbot_certificates"
        with open(mockfile, 'r') as fh:
            self.lines = fh.readlines()
    # def tearDown(self):
    #     pass

    def test_certbot_certificates(self):
        assert type(self.lines) == list

        certbot_certs = setup.certbot_certificates(self.lines)

        assert len(certbot_certs.keys()) == 2

    def test_certbot_certificates_domain(self):
        certbot_certs = setup.certbot_certificates(self.lines)

        cert_path, privkey = setup.get_cert_path_for_domain("test.jumidev.com", certbot_certs)
        print(cert_path)
        print(privkey)
        assert cert_path != None

if __name__ == '__main__':
    unittest.main()
