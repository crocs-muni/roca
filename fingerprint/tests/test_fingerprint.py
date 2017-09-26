#!/usr/bin/env python
# -*- coding: utf-8 -*-

from fingerprint.detect import IontFingerprinter, flatten, drop_none
import random
import base64
import unittest
import pkg_resources


__author__ = 'dusanklinec'


class FprintTest(unittest.TestCase):
    """Simple Fingerprint tests"""

    def __init__(self, *args, **kwargs):
        super(FprintTest, self).__init__(*args, **kwargs)
        self.inputs = []

    def setUp(self):
        """
        Loads testing certs
        :return:
        """
        fls = pkg_resources.resource_listdir(__name__, 'data')
        fls = [x for x in fls if x.endswith('.pem') or x.endswith('.txt')]

        for fname in fls:
            self.inputs.append((fname, self._get_res(fname)))

    def tearDown(self):
        """
        Cleanup
        :return:
        """

    def _get_res(self, name):
        """
        Loads resource
        :param name:
        :return:
        """
        resource_package = __name__
        resource_path = '/'.join(('data', name))
        return pkg_resources.resource_string(resource_package, resource_path)

    def test_fprint(self):
        """
        Test fingerprints
        :return:
        """
        fprinter = IontFingerprinter()
        for fname, data in self.inputs:
            ret = drop_none(flatten(fprinter.process_file(data, fname)))

            if fname.endswith('.pem'):
                self.assertEqual(len(ret), 1, 'PEM expects only one result')
                self.assertEqual(fname, ret[0].fname, 'Filename mismatch')
                self.assertIsNotNone(ret[0].n, 'Modulus is empty')
                self.assertGreaterEqual(len(ret[0].n), 10, 'Modulus is too short')
                self.assertFalse(ret[0].marked, 'PEM certificate %s false positive' % fname)

            elif fname.endswith('.txt'):
                self.assertLessEqual(len(ret), 1, 'Hex mod input epxected result count is 1')
                self.assertEqual(fname, ret[0].fname, 'Filename mismatch')
                self.assertEqual('mod-hex', ret[0].type, 'File type detection failed')
                self.assertIsNotNone(ret[0].n, 'Modulus is empty')
                self.assertGreaterEqual(len(ret[0].n), 10, 'Modulus is too short')

                if fname in ['mod01.txt', 'mod02.txt', 'mod03.txt']:

                    self.assertTrue(ret[0].marked, 'False negative detection on fingerprinted modulus: %s' % fname)
                else:
                    self.assertFalse(ret[0].marked, 'False positive detection on non-fingerprinted modulus %s' % fname)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


