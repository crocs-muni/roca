#!/usr/bin/env python
# -*- coding: utf-8 -*-

from roca.detect import RocaFingerprinter, flatten, drop_none, AutoJSONEncoder
import random
import base64
import unittest
import pkg_resources

from roca.detect_tls import RocaTLSFingerprinter

__author__ = 'dusanklinec'


class TlsTest(unittest.TestCase):
    """TLS fingerprint test"""

    def __init__(self, *args, **kwargs):
        super(TlsTest, self).__init__(*args, **kwargs)

    def setUp(self):
        """
        Loads testing certs
        :return:
        """

    def tearDown(self):
        """
        Cleanup
        :return:
        """

    def test_net(self):
        """
        Test university web - internet access
        TODO: implement in a way internet access is not needed
        :return:
        """
        tls_detect = RocaTLSFingerprinter()
        res = tls_detect.process_tls('google.com', 'google.com')


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


