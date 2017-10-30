#!/usr/bin/env python
# -*- coding: utf-8 -*-

from roca.detect import RocaFingerprinter, flatten, drop_none, AutoJSONEncoder
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
        self.positive_samples = [
            'mod01.txt', 'mod02.txt', 'mod03.txt', 'mod08.txt', 'mod09.txt', 'key04.pgp',
            'cert04.pem', 'cert05.pem', 'ssh06.pub', 'pubkey03.pem', 'privkey05.pem'
        ]

    def setUp(self):
        """
        Loads testing certs
        :return:
        """
        fls = pkg_resources.resource_listdir(__name__, 'data')
        fls = [x for x in fls if
               x.endswith('.pem') or
               x.endswith('.txt') or
               x.endswith('.pub') or
               x.endswith('.pgp') or
               x.endswith('.p7s')]

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

    def test_primorial(self):
        """
        Simple primorial test
        :return:
        """
        fp = RocaFingerprinter()
        m, phi = fp.dlog_fprinter.primorial(167)

        self.assertEqual(m, 962947420735983927056946215901134429196419130606213075415963491270)
        self.assertEqual(phi, 103869096713434131141462689130396531045414801386011361280000000000)

    def fprint_subtest(self, fprinter):
        """
        Basic fingerprinter test
        :param fprinter:
        :return:
        """
        self.assertGreaterEqual(len(self.inputs), 19, 'Some inputs are missing')

        for fname, data in self.inputs:
            ret = drop_none(flatten(fprinter.process_file(data, fname)))
            self.assertGreaterEqual(len(ret), 1, 'At least one result expected')

            if fname.endswith('.txt'):
                self.assertEqual(len(ret), 1, 'Hex mod input epxected result count is 1, not %s' % len(ret))
                self.assertEqual('mod-hex', ret[0].type, 'File type detection failed')

            for sub in ret:
                self.assertIsNone(sub.error, 'Unexpected error with file %s : %s' % (fname, sub.error))
                self.assertEqual(fname, sub.fname, 'Filename mismatch')
                self.assertIsNotNone(sub.n, 'Modulus is empty')
                self.assertGreaterEqual(len(sub.n), 10, 'Modulus is too short')

                if fname in self.positive_samples:
                    self.assertTrue(sub.marked, 'False negative detection on fingerprinted modulus: %s' % fname)
                else:
                    self.assertFalse(sub.marked, 'False positive detection on non-fingerprinted modulus %s' % fname)

    def test_fprint_moduli(self):
        """
        Test fingerprints
        :return:
        """
        fprinter = RocaFingerprinter()
        fprinter.switch_fingerprint_method(True)
        self.assertEqual(fprinter.has_fingerprint, fprinter.has_fingerprint_moduli)
        self.fprint_subtest(fprinter)

    def test_fprint_dlog(self):
        """
        Test fingerprints - dlog method
        :return:
        """
        fprinter = RocaFingerprinter()
        fprinter.switch_fingerprint_method(False)
        self.assertEqual(fprinter.has_fingerprint, fprinter.has_fingerprint_dlog)
        self.fprint_subtest(fprinter)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


